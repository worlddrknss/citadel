package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"github.com/worlddrknss/citadel/internal/acme"
	"github.com/worlddrknss/citadel/internal/config"
	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/memory"
)

// keyStore adds KMS signing keys to the in-memory store, which supports only
// its default key, so CAs can be created in handler tests.
type keyStore struct {
	*memory.Store
	mu   sync.Mutex
	keys map[string]store.KMSKey
}

func (k *keyStore) add(usage, spec string, raw, pub []byte, desc string) store.KMSKey {
	k.mu.Lock()
	defer k.mu.Unlock()
	key := store.KMSKey{ID: cryptoutil.RandomHex(8), MasterKeyRaw: raw, PublicKeyRaw: pub, KeyUsage: usage, KeySpec: spec, Enabled: true, Description: desc, CreatedAt: time.Now()}
	k.keys[key.ID] = key
	return key
}

func (k *keyStore) CreateKey(_ context.Context, desc, usage, spec string) (store.KMSKey, error) {
	raw, pub, u, sp, err := store.GenerateKeyMaterial(usage, spec)
	if err != nil {
		return store.KMSKey{}, err
	}
	return k.add(u, sp, raw, pub, desc), nil
}

func (k *keyStore) ImportSigningKey(_ context.Context, desc string, priv, pub []byte, spec string) (store.KMSKey, error) {
	return k.add(store.KeyUsageSignVerify, spec, priv, pub, desc), nil
}

func (k *keyStore) ResolveByID(ctx context.Context, id string) (store.KMSKey, error) {
	k.mu.Lock()
	key, ok := k.keys[id]
	k.mu.Unlock()
	if ok {
		return key, nil
	}
	return k.Store.ResolveByID(ctx, id)
}

func (k *keyStore) CreateAlias(context.Context, string, string) error { return nil }

type pkiEnv struct {
	t            *testing.T
	s            *Server
	st           store.Store
	h            http.Handler
	acctA, acctB string
	ts           *httptest.Server
}

// newPKIEnv: admin/editor/viewer in account A, "other" admin in account B.
func newPKIEnv(t *testing.T, mod func(*Server)) *pkiEnv {
	t.Helper()
	mem := &memory.Store{DefaultKey: sampleKey(1)}
	return newPKIEnvOn(t, &keyStore{Store: mem, keys: map[string]store.KMSKey{}}, mod)
}

func newPKIEnvOn(t *testing.T, st store.Store, mod func(*Server)) *pkiEnv {
	t.Helper()
	ctx := context.Background()
	mem := st
	e := &pkiEnv{t: t, st: st}
	var err error
	if e.acctA, err = mem.CreateUIAccount(ctx, "alpha"); err != nil {
		t.Fatal(err)
	}
	if e.acctB, err = mem.CreateUIAccount(ctx, "beta"); err != nil {
		t.Fatal(err)
	}
	for _, m := range []struct{ user, acct, role string }{
		{"admin", e.acctA, "admin"}, {"editor", e.acctA, "editor"}, {"viewer", e.acctA, "viewer"}, {"other", e.acctB, "admin"},
	} {
		if err := mem.UpsertUIUser(ctx, store.UIUser{Username: m.user, Role: "viewer", PasswordHash: "x"}); err != nil {
			t.Fatal(err)
		}
		if err := mem.AddUserAccount(ctx, m.user, m.acct, m.role); err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	e.ts = httptest.NewServer(mux)
	t.Cleanup(e.ts.Close)
	e.s = &Server{cfg: config.Config{SessionIdleTTL: 30 * time.Minute, SessionAbsTTL: 12 * time.Hour, PublicURL: e.ts.URL}, store: st}
	if mod != nil {
		mod(e.s)
	}
	e.h = e.s.Handler()
	mux.Handle("/", e.h)
	t.Cleanup(func() {
		if e.s.pki.acmeSrv != nil {
			e.s.pki.acmeSrv.Close()
		}
	})
	return e
}

func (e *pkiEnv) cookie(user string) *http.Cookie {
	e.t.Helper()
	acct := e.acctA
	if user == "other" {
		acct = e.acctB
	}
	token := cryptoutil.RandomHex(32)
	now := time.Now().UTC()
	if err := e.st.CreateConsoleSession(context.Background(), store.ConsoleSession{
		ID: cryptoutil.RandomHex(8), TokenHash: hashSessionToken(token), Username: user, AccountID: acct,
		Method: store.SessionMethodPassword, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		e.t.Fatal(err)
	}
	return &http.Cookie{Name: sessionCookieInsecure, Value: token}
}

func (e *pkiEnv) do(user, method, path string, body any) *httptest.ResponseRecorder {
	e.t.Helper()
	return doReq(e.t, e.h, method, path, body, e.cookie(user))
}

func (e *pkiEnv) createCA(user string, body map[string]any) string {
	e.t.Helper()
	rec := e.do(user, "POST", "/v1/certificates/authorities", body)
	wantStatus(e.t, rec, http.StatusOK)
	return decode(e.t, rec)["caId"].(string)
}

func parsePEMChain(t *testing.T, s string) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	rest := []byte(s)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return out
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
}

func verifyChain(t *testing.T, leaf *x509.Certificate, chain []*x509.Certificate, eku x509.ExtKeyUsage) {
	t.Helper()
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	for _, c := range chain {
		if certIsSelfSigned(c) {
			roots.AddCert(c)
		} else {
			inter.AddCert(c)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{eku}}); err != nil {
		t.Fatalf("leaf does not verify: %v", err)
	}
}

func makeCSRPEM(t *testing.T, cn string, dns ...string) (string, crypto.Signer) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: dns}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), key
}

func TestPKISubordinateChainAndGeneratedKey(t *testing.T) {
	e := newPKIEnv(t, nil)
	root := e.createCA("admin", map[string]any{"caType": "ROOT", "keyAlgorithm": "EC_secp384r1", "commonName": "Root"})
	sub := e.createCA("admin", map[string]any{"caType": "SUBORDINATE", "keyAlgorithm": "RSA_2048", "commonName": "Issuing", "parentCaId": root})

	subRec, err := e.st.GetCertificateAuthorityByID(context.Background(), sub)
	if err != nil || subRec.ParentCAID != root {
		t.Fatalf("sub CA = %+v %v", subRec, err)
	}
	subCert, _ := parseCertificateB64(subRec.CACertB64)
	if subCert.MaxPathLen != 0 || !subCert.MaxPathLenZero {
		t.Fatalf("sub CA path length = %d/%v", subCert.MaxPathLen, subCert.MaxPathLenZero)
	}
	// A pathLen-0 CA cannot sign another CA.
	rec := e.do("admin", "POST", "/v1/certificates/authorities", map[string]any{"caType": "SUBORDINATE", "keyAlgorithm": "EC_prime256v1", "commonName": "Too deep", "parentCaId": sub})
	wantStatus(t, rec, http.StatusConflict)

	rec = e.do("editor", "POST", "/v1/certificates/issue/generate", map[string]any{
		"caId": sub, "commonName": "svc.example.com", "sans": []string{"svc.example.com", "10.0.0.5"}, "template": "client", "keyAlgorithm": "EC_prime256v1", "validityDays": 30,
	})
	wantStatus(t, rec, http.StatusOK)
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("generated key response is cacheable")
	}
	m := decode(t, rec)
	leaf := parsePEMChain(t, m["certificatePem"].(string))[0]
	chain := parsePEMChain(t, m["chainPem"].(string))
	if len(chain) != 2 {
		t.Fatalf("chain has %d certificates", len(chain))
	}
	verifyChain(t, leaf, chain, x509.ExtKeyUsageClientAuth)
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("EKU = %v", leaf.ExtKeyUsage)
	}
	block, _ := pem.Decode([]byte(m["privateKeyPem"].(string)))
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil || !publicKeysEqual(priv.(crypto.Signer).Public(), leaf.PublicKey) {
		t.Fatalf("private key does not match leaf: %v", err)
	}
	if !strings.Contains(rec.Body.String(), "certId") || strings.Contains(rec.Body.String(), "BEGIN RSA") {
		t.Fatal("unexpected response shape")
	}
	// The detail reports the console's template name, not the AWS one.
	rec = e.do("viewer", "GET", "/v1/certificates/detail?source=pca-cert&id="+m["certId"].(string), nil)
	wantStatus(t, rec, http.StatusOK)
	if got := decode(t, rec)["template"]; got != "client" {
		t.Fatalf("detail template = %v, want client", got)
	}
	if !e.audited("citadel.IssueCertificate") {
		t.Fatal("issue not audited")
	}
}

func TestPKIIssueFromCSRListAndRevoke(t *testing.T) {
	e := newPKIEnv(t, nil)
	ca := e.createCA("admin", map[string]any{"caType": "ROOT", "keyAlgorithm": "EC_prime256v1", "commonName": "Root A"})
	csr, _ := makeCSRPEM(t, "web.example.com", "web.example.com")
	rec := e.do("editor", "POST", "/v1/certificates/issue", map[string]any{"caArn": ca, "csrPem": csr, "validityDays": "10", "sanNames": "api.example.com"})
	wantStatus(t, rec, http.StatusOK)
	certID := decode(t, rec)["certId"].(string)

	rec = e.do("viewer", "GET", "/v1/certificates", nil)
	wantStatus(t, rec, http.StatusOK)
	var list struct{ Certificates []nativeCertificate }
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	var row *nativeCertificate
	for i := range list.Certificates {
		if list.Certificates[i].ID == certID {
			row = &list.Certificates[i]
		}
	}
	if row == nil || row.CommonName != "web.example.com" || row.Serial == "" || row.KeyAlgorithm != keyAlgP256 || !row.ExpiringSoon || row.Template != "server" {
		t.Fatalf("row = %+v", row)
	}

	wantStatus(t, e.do("editor", "POST", "/v1/certificates/revoke", map[string]any{"certId": certID, "reason": "KeyCompromise"}), http.StatusForbidden)
	wantStatus(t, e.do("other", "POST", "/v1/certificates/revoke", map[string]any{"certId": certID}), http.StatusNotFound)
	wantStatus(t, e.do("admin", "POST", "/v1/certificates/revoke", map[string]any{"certId": certID, "reason": "KeyCompromise"}), http.StatusOK)
	wantStatus(t, e.do("admin", "POST", "/v1/certificates/revoke", map[string]any{"certId": certID}), http.StatusConflict)
	rec = e.do("viewer", "GET", "/v1/certificates", nil)
	if !strings.Contains(rec.Body.String(), `"revokedAt"`) {
		t.Fatalf("revokedAt missing: %s", rec.Body.String())
	}
	// Renewing keeps the names and gives a new certificate.
	wantStatus(t, e.do("admin", "POST", "/v1/certificates/renew", map[string]any{"certId": certID}), http.StatusConflict)
}

func TestPKIRolesIsolationAndValidation(t *testing.T) {
	e := newPKIEnv(t, nil)
	ca := e.createCA("admin", map[string]any{"caType": "ROOT", "keyAlgorithm": "RSA_3072", "commonName": "Root A"})

	for _, u := range []string{"viewer", "editor"} {
		wantStatus(t, e.do(u, "POST", "/v1/certificates/authorities", map[string]any{"commonName": "x"}), http.StatusForbidden)
	}
	wantStatus(t, e.do("viewer", "POST", "/v1/certificates/issue/generate", map[string]any{"caId": ca}), http.StatusForbidden)

	for name, body := range map[string]map[string]any{
		"bad key":        {"keyAlgorithm": "RSA_1024", "commonName": "x"},
		"no parent":      {"caType": "SUBORDINATE", "commonName": "x"},
		"no cn":          {"keyAlgorithm": "EC_prime256v1"},
		"parent on root": {"caType": "ROOT", "commonName": "x", "parentCaId": ca},
	} {
		if rec := e.do("admin", "POST", "/v1/certificates/authorities", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d %s", name, rec.Code, rec.Body.String())
		}
	}
	for name, body := range map[string]map[string]any{
		"no names":     {"caId": ca, "keyAlgorithm": "EC_prime256v1"},
		"bad alg":      {"caId": ca, "commonName": "a.example", "keyAlgorithm": "ED25519"},
		"bad validity": {"caId": ca, "commonName": "a.example", "keyAlgorithm": "EC_prime256v1", "validityDays": 5000},
		"bad template": {"caId": ca, "commonName": "a.example", "keyAlgorithm": "EC_prime256v1", "template": "codesign"},
	} {
		if rec := e.do("editor", "POST", "/v1/certificates/issue/generate", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d %s", name, rec.Code, rec.Body.String())
		}
	}

	// Account B sees none of A's CAs and cannot issue from or chain to them.
	rec := e.do("other", "GET", "/v1/certificates", nil)
	if strings.Contains(rec.Body.String(), ca) {
		t.Fatal("account B lists account A's CA")
	}
	wantStatus(t, e.do("other", "POST", "/v1/certificates/issue/generate", map[string]any{"caId": ca, "commonName": "a.example", "keyAlgorithm": "EC_prime256v1"}), http.StatusNotFound)
	wantStatus(t, e.do("other", "POST", "/v1/certificates/authorities", map[string]any{"caType": "SUBORDINATE", "commonName": "x", "parentCaId": ca}), http.StatusNotFound)
	csr, _ := makeCSRPEM(t, "x.example.com")
	wantStatus(t, e.do("other", "POST", "/v1/certificates/issue", map[string]any{"caArn": ca, "csrPem": csr}), http.StatusNotFound)
}

func TestPKIEABKeys(t *testing.T) {
	e := newPKIEnv(t, nil)
	wantStatus(t, e.do("editor", "POST", "/v1/certificates/acme/eab", map[string]any{"label": "ci"}), http.StatusForbidden)
	wantStatus(t, e.do("admin", "POST", "/v1/certificates/acme/eab", map[string]any{"label": ""}), http.StatusBadRequest)
	rec := e.do("admin", "POST", "/v1/certificates/acme/eab", map[string]any{"label": "ci"})
	wantStatus(t, rec, http.StatusOK)
	m := decode(t, rec)
	kid := m["kid"].(string)
	if key, err := base64.RawURLEncoding.DecodeString(m["hmacKey"].(string)); err != nil || len(key) != 32 {
		t.Fatalf("hmacKey = %v %v", m["hmacKey"], err)
	}
	rec = e.do("viewer", "GET", "/v1/certificates/acme/eab", nil)
	wantStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"status":"unused"`) || strings.Contains(rec.Body.String(), "hmac") || !strings.Contains(rec.Body.String(), `"createdBy":"admin"`) {
		t.Fatalf("list = %s", rec.Body.String())
	}
	if strings.Contains(e.do("other", "GET", "/v1/certificates/acme/eab", nil).Body.String(), kid) {
		t.Fatal("account B lists account A's EAB key")
	}
	wantStatus(t, e.do("other", "DELETE", "/v1/certificates/acme/eab?kid="+kid, nil), http.StatusNotFound)
	wantStatus(t, e.do("admin", "DELETE", "/v1/certificates/acme/eab", nil), http.StatusBadRequest)
	wantStatus(t, e.do("admin", "DELETE", "/v1/certificates/acme/eab?kid="+kid, nil), http.StatusOK)
	if !strings.Contains(e.do("viewer", "GET", "/v1/certificates/acme/eab", nil).Body.String(), `"status":"revoked"`) {
		t.Fatal("key not revoked")
	}
	if !e.audited("citadel.CreateEABKey") || !e.audited("citadel.RevokeEABKey") {
		t.Fatal("EAB changes not audited")
	}
}

func TestPKIACMESettingsValidation(t *testing.T) {
	e := newPKIEnv(t, nil)
	wantStatus(t, e.do("editor", "POST", "/v1/certificates/acme/settings", map[string]any{}), http.StatusForbidden)
	wantStatus(t, e.do("admin", "POST", "/v1/certificates/acme/settings", map[string]any{"allowedDomains": []string{"*.example.com"}}), http.StatusBadRequest)
	wantStatus(t, e.do("admin", "POST", "/v1/certificates/acme/settings", map[string]any{"validationAllowedCidrs": []string{"nope"}}), http.StatusBadRequest)
	wantStatus(t, e.do("admin", "POST", "/v1/certificates/acme/settings", map[string]any{"issuingCaId": "missing"}), http.StatusNotFound)
	ca := e.createCA("admin", map[string]any{"commonName": "Root A", "keyAlgorithm": "EC_prime256v1"})
	rec := e.do("admin", "POST", "/v1/certificates/acme/settings", map[string]any{"issuingCaId": ca, "allowedDomains": []string{"Example.com."}})
	wantStatus(t, rec, http.StatusOK)
	m := decode(t, rec)
	if m["enabled"] != true || m["effectiveIssuingCaId"] != ca || !strings.HasSuffix(m["directoryUrl"].(string), "/acme/directory") {
		t.Fatalf("settings = %v", m)
	}
	// Another account cannot point its ACME server at A's CA.
	wantStatus(t, e.do("other", "POST", "/v1/certificates/acme/settings", map[string]any{"issuingCaId": ca}), http.StatusNotFound)
}

// TestACMEEndToEnd drives the mounted ACME server with a real ACME client:
// EAB-bound registration, a dns-01 order, issuance from the tenant's CA,
// single-use EAB keys and revocation through the private CA.
func TestACMEEndToEnd(t *testing.T) {
	e := newPKIEnv(t, func(s *Server) {
		s.pki.validators = map[string]acme.Validator{acme.ChallengeDNS01: acme.ValidatorFunc(func(context.Context, acme.Identifier, string, string) error { return nil })}
	})
	runACMEEndToEnd(t, e)
}

func runACMEEndToEnd(t *testing.T, e *pkiEnv) {
	ctx := context.Background()
	ca := e.createCA("admin", map[string]any{"commonName": "ACME Root", "keyAlgorithm": "EC_prime256v1"})
	wantStatus(t, e.do("admin", "POST", "/v1/certificates/acme/settings", map[string]any{"allowedDomains": []string{"example.test"}}), http.StatusOK)
	m := decode(t, e.do("admin", "POST", "/v1/certificates/acme/eab", map[string]any{"label": "e2e"}))
	kid := m["kid"].(string)
	hmacKey, _ := base64.RawURLEncoding.DecodeString(m["hmacKey"].(string))

	acctKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cl := &xacme.Client{Key: acctKey, DirectoryURL: e.ts.URL + "/acme/directory"}
	if _, err := cl.Register(ctx, &xacme.Account{ExternalAccountBinding: &xacme.ExternalAccountBinding{KID: kid, Key: hmacKey}}, xacme.AcceptTOS); err != nil {
		t.Fatalf("register: %v", err)
	}
	// The binding key is single-use.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cl2 := &xacme.Client{Key: otherKey, DirectoryURL: cl.DirectoryURL}
	if _, err := cl2.Register(ctx, &xacme.Account{ExternalAccountBinding: &xacme.ExternalAccountBinding{KID: kid, Key: hmacKey}}, xacme.AcceptTOS); err == nil {
		t.Fatal("EAB key was accepted twice")
	}
	// Names outside the allowed suffixes are rejected.
	if _, err := cl.AuthorizeOrder(ctx, xacme.DomainIDs("www.evil.test")); err == nil {
		t.Fatal("order for a disallowed name succeeded")
	}

	order, err := cl.AuthorizeOrder(ctx, xacme.DomainIDs("www.example.test"))
	if err != nil {
		t.Fatalf("order: %v", err)
	}
	for _, u := range order.AuthzURLs {
		az, err := cl.GetAuthorization(ctx, u)
		if err != nil {
			t.Fatal(err)
		}
		for _, ch := range az.Challenges {
			if ch.Type == "dns-01" {
				if _, err := cl.Accept(ctx, ch); err != nil {
					t.Fatal(err)
				}
			}
		}
		if _, err := cl.WaitAuthorization(ctx, u); err != nil {
			t.Fatalf("authz: %v", err)
		}
	}
	if order, err = cl.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("wait order: %v", err)
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"www.example.test"}}, leafKey)
	ders, _, err := cl.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	leaf, _ := x509.ParseCertificate(ders[0])
	var chain []*x509.Certificate
	for _, d := range ders[1:] {
		c, _ := x509.ParseCertificate(d)
		chain = append(chain, c)
	}
	verifyChain(t, leaf, chain, x509.ExtKeyUsageServerAuth)
	ctxA := store.WithCallerAccount(ctx, e.acctA)
	certs, _ := e.st.ListCertificates(ctxA, ca)
	if len(certs) != 1 || certs[0].Serial != leaf.SerialNumber.String() {
		t.Fatalf("issued certificate not recorded under the tenant's CA: %+v", certs)
	}
	if !e.audited("citadel.ACMEIssueCertificate") {
		t.Fatal("ACME issuance not audited")
	}

	if err := cl.RevokeCert(ctx, nil, ders[0], xacme.CRLReasonKeyCompromise); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	c, _ := e.st.GetCertificate(ctxA, certs[0].CertID)
	if c.Status != "REVOKED" || c.RevocationReason != "KeyCompromise" {
		t.Fatalf("revoked cert = %+v", c)
	}

	// Revoking the EAB key cuts off the account it bound.
	wantStatus(t, e.do("admin", "DELETE", "/v1/certificates/acme/eab?kid="+kid, nil), http.StatusOK)
	if _, err := cl.AuthorizeOrder(ctx, xacme.DomainIDs("www.example.test")); err == nil {
		t.Fatal("account of a revoked EAB key can still order")
	}
}

func TestACMEDisabledWithoutPublicURL(t *testing.T) {
	e := newPKIEnv(t, func(s *Server) { s.cfg.PublicURL = "" })
	rec := doReq(t, e.h, "GET", "/acme/directory", nil, nil)
	wantStatus(t, rec, http.StatusNotFound)
	if !strings.Contains(rec.Body.String(), "not enabled") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestACMERateLimitNonces(t *testing.T) {
	e := newPKIEnv(t, nil)
	limited := false
	for i := 0; i < 40 && !limited; i++ {
		rec := doReq(t, e.h, "HEAD", "/acme/new-nonce", nil, nil)
		limited = rec.Code == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("newNonce was never rate limited")
	}
}

func TestACMESSRFGuard(t *testing.T) {
	ctl := ssrfDialControl(nil)
	for addr, blocked := range map[string]bool{
		"127.0.0.1:80": true, "[::1]:80": true, "169.254.169.254:80": true, "[fe80::1]:80": true,
		"100.100.100.200:80": true, "[fd00:ec2::254]:80": true, "[::ffff:127.0.0.1]:80": true, "0.0.0.0:80": true,
		"10.0.0.5:80": false, "93.184.216.34:80": false,
	} {
		if err := ctl(context.Background(), "tcp", addr, nil); (err != nil) != blocked {
			t.Errorf("%s: err=%v, want blocked=%v", addr, err, blocked)
		}
	}
	if err := ssrfDialControl([]string{"127.0.0.0/8"})(context.Background(), "tcp", "127.0.0.1:80", nil); err != nil {
		t.Errorf("explicitly allowed loopback blocked: %v", err)
	}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer site.Close()
	if _, err := ssrfHTTPClient(nil).Get(site.URL); err == nil {
		t.Fatal("guarded client reached a loopback server")
	}
	resp, err := ssrfHTTPClient([]string{"127.0.0.1"}).Get(site.URL)
	if err != nil {
		t.Fatalf("allowed loopback: %v", err)
	}
	resp.Body.Close()

	e := newPKIEnv(t, nil)
	ctx := store.WithCallerAccount(context.Background(), e.acctA)
	_ = e.st.PutACMEServerSettings(ctx, store.ACMEServerSettings{AllowedDomains: []string{"example.test"}, AllowedIPRanges: []string{"127.0.0.0/8", "10.0.0.0/8"}})
	p := acmePolicy{s: e.s}
	for id, ok := range map[acme.Identifier]bool{
		{Type: "dns", Value: "a.example.test"}:  true,
		{Type: "dns", Value: "*.example.test"}:  true,
		{Type: "dns", Value: "example.testing"}: false,
		{Type: "ip", Value: "10.1.2.3"}:         true,
		{Type: "ip", Value: "127.0.0.1"}:        false, // in range but loopback
		{Type: "ip", Value: "192.168.1.1"}:      false,
	} {
		if err := p.Allow(context.Background(), e.acctA, id); (err == nil) != ok {
			t.Errorf("%v: err=%v want ok=%v", id, err, ok)
		}
	}
	if err := p.Allow(context.Background(), e.acctB, acme.Identifier{Type: "dns", Value: "a.example.test"}); err == nil {
		t.Error("account B may use account A's domains")
	}
}

func TestCertificateExpiryJob(t *testing.T) {
	e := newPKIEnv(t, nil)
	ca := e.createCA("admin", map[string]any{"commonName": "Root A", "keyAlgorithm": "EC_prime256v1"})
	ctxA := store.WithCallerAccount(context.Background(), e.acctA)
	past := time.Now().Add(-time.Hour)
	if err := e.st.CreateCertificate(ctxA, store.PCACertificate{CertID: "old", CAID: ca, Serial: "77", Status: "ISSUED", NotBefore: past.Add(-time.Hour), NotAfter: past, CreatedAt: past}); err != nil {
		t.Fatal(err)
	}
	if n := e.s.markExpiredCertificates(context.Background(), time.Now()); n != 1 {
		t.Fatalf("expired %d", n)
	}
	c, _ := e.st.GetCertificate(ctxA, "old")
	if c.Status != "EXPIRED" {
		t.Fatalf("status %s", c.Status)
	}
}

// audited reports whether account A's audit log holds a successful action.
func (e *pkiEnv) audited(action string) bool {
	e.t.Helper()
	events, err := e.st.QueryAuditEvents(store.WithCallerAccount(context.Background(), e.acctA), store.AuditQuery{Limit: 500})
	if err != nil {
		e.t.Fatal(err)
	}
	for _, ev := range events {
		if ev.Action == action && store.NormalizeAuditResult(ev.Result, ev.ErrorType) == store.AuditResultSuccess {
			return true
		}
	}
	return false
}
