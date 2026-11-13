package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// testCert issues a certificate for cn signed by parent (self-signed when
// parent is nil).
func testCert(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		BasicConstraintsValid: true, IsCA: isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.DNSNames = []string{cn}
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

// importACM stores an imported ACM certificate in account A the way
// ImportCertificate does.
func (e *pkiEnv) importACM(leaf *x509.Certificate, chain ...*x509.Certificate) string {
	e.t.Helper()
	var chainPEM strings.Builder
	for _, c := range chain {
		chainPEM.Write(encodeCertificatePEM(c.Raw))
	}
	ctx := store.WithCallerAccount(context.Background(), e.acctA)
	now := time.Now().UTC()
	c := store.ACMCertificate{
		ARN: e.s.acmCertARN(ctx, cryptoutil.RandomHex(16)), Type: store.ACMTypeImported,
		DomainName: leaf.Subject.CommonName, SANs: leaf.DNSNames, Serial: leaf.SerialNumber.String(),
		CertB64: base64.StdEncoding.EncodeToString(leaf.Raw), ChainPEM: chainPEM.String(), KeyDER: []byte{1},
		Status: "ISSUED", NotBefore: leaf.NotBefore.UTC(), NotAfter: leaf.NotAfter.UTC(), CreatedAt: now, UpdatedAt: now,
	}
	if err := e.st.CreateACMCertificate(ctx, c); err != nil {
		e.t.Fatal(err)
	}
	return c.ARN
}

func (e *pkiEnv) listRows(user string) []nativeCertificate {
	e.t.Helper()
	rec := e.do(user, "GET", "/v1/certificates", nil)
	wantStatus(e.t, rec, http.StatusOK)
	var list struct{ Certificates []nativeCertificate }
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		e.t.Fatal(err)
	}
	return list.Certificates
}

func (e *pkiEnv) detail(user, source, id string) nativeCertificateDetail {
	e.t.Helper()
	rec := e.do(user, "GET", "/v1/certificates/detail?"+url.Values{"source": {source}, "id": {id}}.Encode(), nil)
	wantStatus(e.t, rec, http.StatusOK)
	var d nativeCertificateDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		e.t.Fatal(err)
	}
	return d
}

func wantChain(t *testing.T, got []nativeChainCert, want []*x509.Certificate, roles ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("chain has %d certificates, want %d: %+v", len(got), len(want), got)
	}
	for i, c := range want {
		g := got[i]
		if g.Subject != c.Subject.String() || g.Issuer != c.Issuer.String() || g.Role != roles[i] || g.NotAfter != fmtTime(c.NotAfter) || g.NotBefore != fmtTime(c.NotBefore) {
			t.Fatalf("chain[%d] = %+v, want %s (%s)", i, g, c.Subject, roles[i])
		}
		if p := parsePEMChain(t, g.PEM); len(p) != 1 || !p[0].Equal(c) {
			t.Fatalf("chain[%d] PEM does not match", i)
		}
	}
}

func TestImportedCertificatesListDetailChain(t *testing.T) {
	e := newPKIEnv(t, nil)
	root, rootKey := testCert(t, "External Root", true, nil, nil)
	inter, interKey := testCert(t, "External Issuing", true, root, rootKey)
	leaf, _ := testCert(t, "imported.example.com", false, inter, interKey)
	// The importer sent the chain root-first; order must not matter.
	arn := e.importACM(leaf, root, inter)

	var row *nativeCertificate
	for _, r := range e.listRows("viewer") {
		if r.ID == arn {
			row = &r
		}
	}
	if row == nil || row.Source != sourceACMImported || row.CommonName != "imported.example.com" || row.Status != "ISSUED" ||
		row.Issuer != inter.Subject.String() || row.KeyAlgorithm != keyAlgP256 || row.NotAfter == "" {
		t.Fatalf("row = %+v", row)
	}

	d := e.detail("viewer", sourceACMImported, arn)
	if d.Source != sourceACMImported || d.ID != arn || d.Issuer != inter.Subject.String() || !strings.Contains(d.PEM, "BEGIN CERTIFICATE") || d.ChainPEM == "" {
		t.Fatalf("detail = %+v", d)
	}
	wantChain(t, d.Chain, []*x509.Certificate{leaf, inter, root}, "leaf", "intermediate", "root")
	if !d.Chain[2].SelfSigned || d.Chain[0].IsCA || !d.Chain[1].IsCA {
		t.Fatalf("chain flags = %+v", d.Chain)
	}

	// Without the root in the stored chain the chain stops at the last issuer
	// Citadel holds; that element is not labelled a root.
	arn2 := e.importACM(leaf, inter)
	d = e.detail("viewer", sourceACMImported, arn2)
	wantChain(t, d.Chain, []*x509.Certificate{leaf, inter}, "leaf", "intermediate")

	// Other accounts see none of it.
	for _, r := range e.listRows("other") {
		if r.ID == arn {
			t.Fatal("account B lists account A's imported certificate")
		}
	}
	wantStatus(t, e.do("other", "GET", "/v1/certificates/detail?"+url.Values{"source": {sourceACMImported}, "id": {arn}}.Encode(), nil), http.StatusNotFound)
}

func TestCertificateDetailChainToCitadelRoot(t *testing.T) {
	e := newPKIEnv(t, nil)
	rootID := e.createCA("admin", map[string]any{"caType": "ROOT", "keyAlgorithm": "EC_prime256v1", "commonName": "Chain Root"})
	subID := e.createCA("admin", map[string]any{"caType": "SUBORDINATE", "keyAlgorithm": "EC_prime256v1", "commonName": "Chain Issuing", "parentCaId": rootID})
	rec := e.do("editor", "POST", "/v1/certificates/issue/generate", map[string]any{"caId": subID, "commonName": "svc.example.com", "keyAlgorithm": "EC_prime256v1", "validityDays": 30})
	wantStatus(t, rec, http.StatusOK)
	m := decode(t, rec)
	leaf := parsePEMChain(t, m["certificatePem"].(string))[0]

	ctx := store.WithCallerAccount(context.Background(), e.acctA)
	rootRec, _ := e.st.GetCertificateAuthorityByID(ctx, rootID)
	subRec, _ := e.st.GetCertificateAuthorityByID(ctx, subID)
	root, _ := parseCertificateB64(rootRec.CACertB64)
	sub, _ := parseCertificateB64(subRec.CACertB64)

	d := e.detail("viewer", "pca-cert", m["certId"].(string))
	wantChain(t, d.Chain, []*x509.Certificate{leaf, sub, root}, "leaf", "intermediate", "root")

	d = e.detail("viewer", "pca-ca", subID)
	wantChain(t, d.Chain, []*x509.Certificate{sub, root}, "intermediate", "root")
	d = e.detail("viewer", "pca-ca", rootID)
	wantChain(t, d.Chain, []*x509.Certificate{root}, "root")

	// A certificate a Citadel CA issued and then imported without a chain
	// still resolves to the root through the account's CAs.
	arn := e.importACM(leaf)
	d = e.detail("viewer", sourceACMImported, arn)
	wantChain(t, d.Chain, []*x509.Certificate{leaf, sub, root}, "leaf", "intermediate", "root")
}

func TestDeleteImportedCertificate(t *testing.T) {
	e := newPKIEnv(t, nil)
	root, rootKey := testCert(t, "External Root", true, nil, nil)
	leaf, _ := testCert(t, "gone.example.com", false, root, rootKey)
	arn := e.importACM(leaf, root)
	path := "/v1/certificates/acm?" + url.Values{"arn": {arn}}.Encode()

	wantStatus(t, e.do("viewer", "DELETE", path, nil), http.StatusForbidden)
	wantStatus(t, e.do("editor", "DELETE", path, nil), http.StatusForbidden)
	wantStatus(t, e.do("other", "DELETE", path, nil), http.StatusNotFound)
	wantStatus(t, e.do("admin", "DELETE", "/v1/certificates/acm", nil), http.StatusBadRequest)
	rec := e.do("admin", "DELETE", path, nil)
	wantStatus(t, rec, http.StatusOK)
	if decode(t, rec)["deleted"] != true {
		t.Fatalf("delete = %s", rec.Body.String())
	}
	if !e.audited("citadel.DeleteImportedCertificate") {
		t.Fatal("delete not audited")
	}
	for _, r := range e.listRows("admin") {
		if r.ID == arn {
			t.Fatal("deleted certificate still listed")
		}
	}
	wantStatus(t, e.do("admin", "DELETE", path, nil), http.StatusNotFound)

	// Certificates Citadel issued through ACM are not deleted from here.
	ctx := store.WithCallerAccount(context.Background(), e.acctA)
	priv := store.ACMCertificate{ARN: e.s.acmCertARN(ctx, "private1"), Type: store.ACMTypePrivate, DomainName: "p.example.com",
		CertB64: base64.StdEncoding.EncodeToString(leaf.Raw), Status: "ISSUED", NotAfter: leaf.NotAfter, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := e.st.CreateACMCertificate(ctx, priv); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, e.do("admin", "DELETE", "/v1/certificates/acm?"+url.Values{"arn": {priv.ARN}}.Encode(), nil), http.StatusBadRequest)
	for _, r := range e.listRows("admin") {
		if r.ID == priv.ARN {
			t.Fatal("private ACM certificate listed as imported")
		}
	}
}
