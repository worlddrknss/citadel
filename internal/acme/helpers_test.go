package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- test issuer: a throwaway ECDSA P-256 CA ----

type testIssuer struct {
	mu      sync.Mutex
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
	pem     []byte
	revoked map[string]int
	reqs    []IssueRequest
	fail    error
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test ACME CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testIssuer{
		key: key, cert: cert,
		pem:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		revoked: map[string]int{},
	}
}

func (ti *testIssuer) Issue(_ context.Context, req IssueRequest) ([]byte, error) {
	ti.mu.Lock()
	defer ti.mu.Unlock()
	if ti.fail != nil {
		return nil, ti.fail
	}
	ti.reqs = append(ti.reqs, req)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	notAfter := req.NotAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      req.CSR.Subject,
		DNSNames:     req.CSR.DNSNames,
		IPAddresses:  req.CSR.IPAddresses,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ti.cert, req.CSR.PublicKey, ti.key)
	if err != nil {
		return nil, err
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ti.pem...), nil
}

func (ti *testIssuer) Revoke(_ context.Context, serial *big.Int, reason int) error {
	ti.mu.Lock()
	defer ti.mu.Unlock()
	k := serial.Text(16)
	if _, ok := ti.revoked[k]; ok {
		return ErrAlreadyRevoked
	}
	ti.revoked[k] = reason
	return nil
}

// ---- challenge fixtures ----

type challengeSite struct {
	mu        sync.Mutex
	responses map[string]string // token -> body
}

func (cs *challengeSite) set(token, body string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.responses[token] = body
}

func (cs *challengeSite) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.URL.Path, "/.well-known/acme-challenge/")
	cs.mu.Lock()
	body, found := cs.responses[token]
	cs.mu.Unlock()
	if !ok || !found {
		http.NotFound(w, r)
		return
	}
	io.WriteString(w, body+"\n")
}

type fakeResolver struct {
	mu      sync.Mutex
	records map[string][]string
}

func (f *fakeResolver) set(name string, values ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[name] = values
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.records[name]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return v, nil
}

// clientToSite returns an HTTP client whose every connection goes to site,
// standing in for "the host named in the URL, port 80".
func clientToSite(site *httptest.Server) *http.Client {
	addr := site.Listener.Addr().String()
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		},
	}}
}

// ---- test environment ----

type testEnv struct {
	t      *testing.T
	srv    *Server
	ts     *httptest.Server
	store  *MemoryStore
	issuer *testIssuer
	site   *challengeSite
	dns    *fakeResolver
	base   string
}

func allowAll() Policy {
	return PolicyFunc(func(context.Context, string, Identifier) error { return nil })
}

func newEnv(t *testing.T, mod func(*Config)) *testEnv {
	t.Helper()
	env := &testEnv{
		t:      t,
		store:  NewMemoryStore(),
		issuer: newTestIssuer(t),
		site:   &challengeSite{responses: map[string]string{}},
		dns:    &fakeResolver{records: map[string][]string{}},
	}
	siteTS := httptest.NewServer(env.site)
	t.Cleanup(siteTS.Close)

	mux := http.NewServeMux()
	env.ts = httptest.NewServer(mux)
	t.Cleanup(env.ts.Close)
	env.base = env.ts.URL + "/acme"

	cfg := Config{
		BaseURL: env.base,
		Store:   env.store,
		Issuer:  env.issuer,
		Policy:  allowAll(),
		Validators: map[string]Validator{
			ChallengeHTTP01: HTTP01Validator{Client: clientToSite(siteTS)},
			ChallengeDNS01:  DNS01Validator{Resolver: env.dns},
		},
		TermsOfService: "https://example.test/tos",
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if mod != nil {
		mod(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	env.srv = srv
	t.Cleanup(func() { srv.Close() })
	mux.Handle("/acme/", srv)
	return env
}

// ---- minimal ACME client ----

type response struct {
	status int
	header http.Header
	body   []byte
}

func (r *response) problem() *Problem {
	if !strings.HasPrefix(r.header.Get("Content-Type"), "application/problem+json") {
		return nil
	}
	var p Problem
	if json.Unmarshal(r.body, &p) != nil {
		return nil
	}
	return &p
}

func (r *response) decode(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("decoding %s: %v", r.body, err)
	}
}

type client struct {
	t     *testing.T
	env   *testEnv
	key   crypto.Signer
	alg   string
	kid   string
	nonce string
	dir   directoryJSON
}

func genKey(t *testing.T, alg string) crypto.Signer {
	t.Helper()
	var k crypto.Signer
	var err error
	switch alg {
	case algES256:
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case algES384:
		k, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case algRS256, algPS256:
		k, err = rsa.GenerateKey(rand.Reader, 2048)
	case algEdDSA:
		_, k, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil || k == nil {
		t.Fatalf("generating %s key: %v", alg, err)
	}
	return k
}

func (env *testEnv) newClient(alg string) *client {
	c := &client{t: env.t, env: env, key: genKey(env.t, alg), alg: alg}
	resp := c.do(http.MethodGet, env.base+"/directory", nil)
	if resp.status != http.StatusOK {
		env.t.Fatalf("directory: %d %s", resp.status, resp.body)
	}
	resp.decode(env.t, &c.dir)
	return c
}

func (c *client) do(method, url string, body []byte) *response {
	c.t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/jose+json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if n := resp.Header.Get("Replay-Nonce"); n != "" {
		c.nonce = n
	}
	return &response{status: resp.StatusCode, header: resp.Header, body: b}
}

func (c *client) getNonce() string {
	c.t.Helper()
	if c.nonce == "" {
		resp := c.do(http.MethodHead, c.dir.NewNonce, nil)
		if resp.status != http.StatusOK || c.nonce == "" {
			c.t.Fatalf("newNonce: %d", resp.status)
		}
	}
	n := c.nonce
	c.nonce = ""
	return n
}

func jwkJSON(t *testing.T, pub crypto.PublicKey) json.RawMessage {
	t.Helper()
	b, err := canonicalJWK(pub)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func signWith(t *testing.T, key crypto.Signer, alg string, input []byte) []byte {
	t.Helper()
	switch alg {
	case algES256, algES384:
		k := key.(*ecdsa.PrivateKey)
		var digest []byte
		size := 32
		if alg == algES384 {
			d := sha512.Sum384(input)
			digest, size = d[:], 48
		} else {
			d := sha256.Sum256(input)
			digest = d[:]
		}
		r, s, err := ecdsa.Sign(rand.Reader, k, digest)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]byte, 2*size)
		r.FillBytes(out[:size])
		s.FillBytes(out[size:])
		return out
	case algRS256:
		d := sha256.Sum256(input)
		sig, err := rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, d[:])
		if err != nil {
			t.Fatal(err)
		}
		return sig
	case algPS256:
		d := sha256.Sum256(input)
		sig, err := rsa.SignPSS(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			t.Fatal(err)
		}
		return sig
	case algEdDSA:
		return ed25519.Sign(key.(ed25519.PrivateKey), input)
	}
	t.Fatalf("unknown alg %s", alg)
	return nil
}

// buildJWS assembles a flattened JWS; sign receives the signing input.
func buildJWS(t *testing.T, protected map[string]any, payload []byte, sign func([]byte) []byte) []byte {
	t.Helper()
	ph, err := json.Marshal(protected)
	if err != nil {
		t.Fatal(err)
	}
	p64 := b64enc(ph)
	pl64 := b64enc(payload)
	sig := sign([]byte(p64 + "." + pl64))
	out, _ := json.Marshal(map[string]string{"protected": p64, "payload": pl64, "signature": b64enc(sig)})
	return out
}

func marshalPayload(t *testing.T, payload any) []byte {
	t.Helper()
	if payload == nil {
		return nil // POST-as-GET
	}
	if b, ok := payload.([]byte); ok {
		return b
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// signed builds a request body signed by the client's key, using kid once
// registered and jwk before that.
func (c *client) signed(url string, payload any) []byte {
	c.t.Helper()
	h := map[string]any{"alg": c.alg, "nonce": c.getNonce(), "url": url}
	if c.kid != "" {
		h["kid"] = c.kid
	} else {
		h["jwk"] = jwkJSON(c.t, c.key.Public())
	}
	return buildJWS(c.t, h, marshalPayload(c.t, payload), func(in []byte) []byte { return signWith(c.t, c.key, c.alg, in) })
}

func (c *client) post(url string, payload any) *response {
	c.t.Helper()
	return c.do(http.MethodPost, url, c.signed(url, payload))
}

func (c *client) thumbprint() string {
	tp, err := Thumbprint(c.key.Public())
	if err != nil {
		c.t.Fatal(err)
	}
	return tp
}

func expectStatus(t *testing.T, r *response, status int) {
	t.Helper()
	if r.status != status {
		t.Fatalf("status = %d, want %d; body %s", r.status, status, r.body)
	}
}

func expectProblem(t *testing.T, r *response, typ string) *Problem {
	t.Helper()
	p := r.problem()
	if p == nil {
		t.Fatalf("expected problem %s, got %d %s", typ, r.status, r.body)
	}
	if p.Type != typ {
		t.Fatalf("problem type = %s, want %s (detail %q)", p.Type, typ, p.Detail)
	}
	if p.Status != r.status {
		t.Fatalf("problem status %d != HTTP status %d", p.Status, r.status)
	}
	return p
}

func (c *client) register() {
	c.t.Helper()
	resp := c.post(c.dir.NewAccount, map[string]any{"termsOfServiceAgreed": true, "contact": []string{"mailto:ops@example.com"}})
	expectStatus(c.t, resp, http.StatusCreated)
	c.kid = resp.header.Get("Location")
	if c.kid == "" {
		c.t.Fatal("no account Location")
	}
}

func identifiers(values ...string) []Identifier {
	var out []Identifier
	for _, v := range values {
		typ := IdentifierDNS
		if net.ParseIP(v) != nil {
			typ = IdentifierIP
		}
		out = append(out, Identifier{Type: typ, Value: v})
	}
	return out
}

func (c *client) newOrder(values ...string) (string, orderJSON) {
	c.t.Helper()
	resp := c.post(c.dir.NewOrder, map[string]any{"identifiers": identifiers(values...)})
	expectStatus(c.t, resp, http.StatusCreated)
	var o orderJSON
	resp.decode(c.t, &o)
	return resp.header.Get("Location"), o
}

func (c *client) getOrder(url string) orderJSON {
	c.t.Helper()
	resp := c.post(url, nil)
	expectStatus(c.t, resp, http.StatusOK)
	var o orderJSON
	resp.decode(c.t, &o)
	return o
}

func (c *client) getAuthz(url string) authzJSON {
	c.t.Helper()
	resp := c.post(url, nil)
	expectStatus(c.t, resp, http.StatusOK)
	var a authzJSON
	resp.decode(c.t, &a)
	return a
}

func findChallenge(t *testing.T, a authzJSON, typ string) challengeJSON {
	t.Helper()
	for _, ch := range a.Challenges {
		if ch.Type == typ {
			return ch
		}
	}
	t.Fatalf("authz %s has no %s challenge", a.Identifier.Value, typ)
	return challengeJSON{}
}

// solve provisions the response for the challenge and triggers it.
func (c *client) solve(a authzJSON, typ string) {
	c.t.Helper()
	ch := findChallenge(c.t, a, typ)
	ka := ch.Token + "." + c.thumbprint()
	switch typ {
	case ChallengeHTTP01:
		c.env.site.set(ch.Token, ka)
	case ChallengeDNS01:
		c.env.dns.set("_acme-challenge."+a.Identifier.Value, "unrelated", DNS01Digest(ka))
	}
	resp := c.post(ch.URL, map[string]any{})
	expectStatus(c.t, resp, http.StatusOK)
}

func (c *client) waitAuthz(url string) authzJSON {
	c.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		a := c.getAuthz(url)
		if a.Status != StatusPending {
			return a
		}
		if time.Now().After(deadline) {
			c.t.Fatalf("authz %s still pending", url)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func makeCSR(t *testing.T, key crypto.Signer, cn string, values ...string) []byte {
	t.Helper()
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	for _, v := range values {
		if ip := net.ParseIP(v); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, v)
		}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (c *client) finalize(o orderJSON, csr []byte) *response {
	c.t.Helper()
	return c.post(o.Finalize, map[string]string{"csr": b64enc(csr)})
}

// obtain runs the whole flow for names using the given challenge type and
// returns the leaf certificate, its key and the order.
func (c *client) obtain(typ string, names ...string) (*x509.Certificate, crypto.Signer, orderJSON) {
	c.t.Helper()
	orderURL, o := c.newOrder(names...)
	for _, az := range o.Authorizations {
		a := c.getAuthz(az)
		c.solve(a, typ)
		if got := c.waitAuthz(az); got.Status != StatusValid {
			c.t.Fatalf("authz %s: %s (%+v)", a.Identifier.Value, got.Status, got.Challenges)
		}
	}
	if o = c.getOrder(orderURL); o.Status != StatusReady {
		c.t.Fatalf("order status %s, want ready", o.Status)
	}
	certKey := genKey(c.t, algES256)
	resp := c.finalize(o, makeCSR(c.t, certKey, "", names...))
	expectStatus(c.t, resp, http.StatusOK)
	resp.decode(c.t, &o)
	if o.Status != StatusValid || o.Certificate == "" {
		c.t.Fatalf("finalized order: %+v", o)
	}
	cr := c.post(o.Certificate, nil)
	expectStatus(c.t, cr, http.StatusOK)
	if ct := cr.header.Get("Content-Type"); ct != "application/pem-certificate-chain" {
		c.t.Fatalf("certificate Content-Type %q", ct)
	}
	block, rest := pem.Decode(cr.body)
	if block == nil {
		c.t.Fatal("no PEM in certificate response")
	}
	if ca, _ := pem.Decode(rest); ca == nil {
		c.t.Fatal("chain lacks the CA certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		c.t.Fatal(err)
	}
	return leaf, certKey, o
}

func (c *client) revoke(cert *x509.Certificate, reason int) *response {
	c.t.Helper()
	return c.post(c.dir.RevokeCert, map[string]any{"certificate": b64enc(cert.Raw), "reason": reason})
}

func mustf(t *testing.T, cond bool, format string, args ...any) {
	t.Helper()
	if !cond {
		t.Fatalf(format, args...)
	}
}

func parseChainLeaf(t *testing.T, chain []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(chain)
	if block == nil {
		t.Fatal("no PEM block")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}
