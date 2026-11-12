package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestBadSignature(t *testing.T) {
	env := newEnv(t, nil)
	c := env.newClient(algES256)
	h := map[string]any{"alg": algES256, "nonce": c.getNonce(), "url": c.dir.NewAccount, "jwk": jwkJSON(t, c.key.Public())}
	body := buildJWS(t, h, []byte(`{"termsOfServiceAgreed":true}`), func(in []byte) []byte {
		sig := signWith(t, c.key, algES256, in)
		sig[5] ^= 0xff
		return sig
	})
	resp := c.do(http.MethodPost, c.dir.NewAccount, body)
	expectProblem(t, resp, ProbMalformed)

	// Signed by a different key than the embedded jwk.
	other := genKey(t, algES256)
	h["nonce"] = c.getNonce()
	body = buildJWS(t, h, []byte(`{"termsOfServiceAgreed":true}`), func(in []byte) []byte { return signWith(t, other, algES256, in) })
	expectProblem(t, c.do(http.MethodPost, c.dir.NewAccount, body), ProbMalformed)
}

func TestReusedNonce(t *testing.T) {
	env := newEnv(t, nil)
	c := env.newClient(algES256)
	body := c.signed(c.dir.NewAccount, map[string]any{"termsOfServiceAgreed": true})
	expectStatus(t, c.do(http.MethodPost, c.dir.NewAccount, body), http.StatusCreated)
	resp := c.do(http.MethodPost, c.dir.NewAccount, body)
	expectProblem(t, resp, ProbBadNonce)
	mustf(t, resp.header.Get("Replay-Nonce") != "", "badNonce response lacks a fresh Replay-Nonce")

	// A made-up nonce is rejected as well, and so is a missing one.
	h := map[string]any{"alg": algES256, "nonce": "bm90LWEtbm9uY2U", "url": c.dir.NewAccount, "jwk": jwkJSON(t, c.key.Public())}
	sign := func(in []byte) []byte { return signWith(t, c.key, algES256, in) }
	expectProblem(t, c.do(http.MethodPost, c.dir.NewAccount, buildJWS(t, h, []byte(`{}`), sign)), ProbBadNonce)
	delete(h, "nonce")
	expectProblem(t, c.do(http.MethodPost, c.dir.NewAccount, buildJWS(t, h, []byte(`{}`), sign)), ProbBadNonce)
}

func TestExpiredNonce(t *testing.T) {
	env := newEnv(t, func(cfg *Config) { cfg.NonceLifetime = 1 })
	c := env.newClient(algES256)
	expectProblem(t, c.post(c.dir.NewAccount, map[string]any{"termsOfServiceAgreed": true}), ProbBadNonce)
}

func TestURLMismatch(t *testing.T) {
	env := newEnv(t, nil)
	c := env.newClient(algES256)
	body := c.signed(c.dir.NewOrder, map[string]any{"termsOfServiceAgreed": true})
	expectProblem(t, c.do(http.MethodPost, c.dir.NewAccount, body), ProbUnauthorized)

	h := map[string]any{"alg": algES256, "nonce": c.getNonce(), "jwk": jwkJSON(t, c.key.Public())}
	body = buildJWS(t, h, []byte(`{}`), func(in []byte) []byte { return signWith(t, c.key, algES256, in) })
	expectProblem(t, c.do(http.MethodPost, c.dir.NewAccount, body), ProbMalformed)
}

func TestKidForUnknownAccount(t *testing.T) {
	env := newEnv(t, nil)
	c := env.newClient(algES256)
	c.kid = env.base + "/acct/doesnotexist"
	expectProblem(t, c.post(c.dir.NewOrder, map[string]any{"identifiers": identifiers("a.example.com")}), ProbAccountDoesNotExist)
	c.kid = "https://elsewhere.example/acct/x"
	expectProblem(t, c.post(c.dir.NewOrder, map[string]any{"identifiers": identifiers("a.example.com")}), ProbAccountDoesNotExist)
}

func TestKeyReferenceRules(t *testing.T) {
	env := newEnv(t, nil)
	c := env.newClient(algES256)
	c.register()
	sign := func(in []byte) []byte { return signWith(t, c.key, algES256, in) }

	// jwk where kid is required.
	h := map[string]any{"alg": algES256, "nonce": c.getNonce(), "url": c.dir.NewOrder, "jwk": jwkJSON(t, c.key.Public())}
	expectProblem(t, c.do(http.MethodPost, c.dir.NewOrder, buildJWS(t, h, []byte(`{}`), sign)), ProbMalformed)
	// kid on newAccount.
	h = map[string]any{"alg": algES256, "nonce": c.getNonce(), "url": c.dir.NewAccount, "kid": c.kid}
	expectProblem(t, c.do(http.MethodPost, c.dir.NewAccount, buildJWS(t, h, []byte(`{}`), sign)), ProbMalformed)
	// Both.
	h = map[string]any{"alg": algES256, "nonce": c.getNonce(), "url": c.dir.NewOrder, "kid": c.kid, "jwk": jwkJSON(t, c.key.Public())}
	expectProblem(t, c.do(http.MethodPost, c.dir.NewOrder, buildJWS(t, h, []byte(`{}`), sign)), ProbMalformed)
	// Unprotected header member is not allowed.
	body := c.signed(c.dir.NewOrder, map[string]any{"identifiers": identifiers("a.example.com")})
	var m map[string]any
	json.Unmarshal(body, &m)
	m["header"] = map[string]string{"kid": c.kid}
	body, _ = json.Marshal(m)
	expectProblem(t, c.do(http.MethodPost, c.dir.NewOrder, body), ProbMalformed)
	// Wrong content type.
	req, _ := http.NewRequest(http.MethodPost, c.dir.NewOrder, strings.NewReader(string(c.signed(c.dir.NewOrder, nil))))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	mustf(t, err == nil && resp.StatusCode == http.StatusUnsupportedMediaType, "content type check: %v %v", resp, err)
	resp.Body.Close()
}

func TestRejectedAlgorithms(t *testing.T) {
	env := newEnv(t, nil)
	c := env.newClient(algES256)
	for _, alg := range []string{"none", "HS256", "ES512", "RS1"} {
		h := map[string]any{"alg": alg, "nonce": c.getNonce(), "url": c.dir.NewAccount, "jwk": jwkJSON(t, c.key.Public())}
		body := buildJWS(t, h, []byte(`{"termsOfServiceAgreed":true}`), func(in []byte) []byte {
			if alg == "none" {
				return nil
			}
			return hmacSHA256([]byte(strings.Repeat("s", 32)), in)
		})
		p := expectProblem(t, c.do(http.MethodPost, c.dir.NewAccount, body), ProbBadSignatureAlgorithm)
		mustf(t, len(p.Algorithms) > 0, "badSignatureAlgorithm should list algorithms")
	}
	// alg/key mismatch: ES384 header with a P-256 key.
	h := map[string]any{"alg": algES384, "nonce": c.getNonce(), "url": c.dir.NewAccount, "jwk": jwkJSON(t, c.key.Public())}
	body := buildJWS(t, h, []byte(`{}`), func(in []byte) []byte { return signWith(t, c.key, algES256, in) })
	expectProblem(t, c.do(http.MethodPost, c.dir.NewAccount, body), ProbBadSignatureAlgorithm)
}

func TestWeakAndUnsupportedKeys(t *testing.T) {
	env := newEnv(t, nil)
	c := env.newClient(algES256)

	// RSA-1024 cannot even be generated in FIPS-only mode, so build the JWK
	// from an arbitrary odd 1024-bit modulus; the server must reject it
	// before attempting verification.
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 1023))
	n.SetBit(n, 1023, 1).SetBit(n, 0, 1)
	weak := json.RawMessage(`{"kty":"RSA","n":"` + b64enc(n.Bytes()) + `","e":"AQAB"}`)
	h := map[string]any{"alg": algRS256, "nonce": c.getNonce(), "url": c.dir.NewAccount, "jwk": weak}
	body := buildJWS(t, h, []byte(`{"termsOfServiceAgreed":true}`), func([]byte) []byte { return make([]byte, 128) })
	expectProblem(t, c.do(http.MethodPost, c.dir.NewAccount, body), ProbBadPublicKey)

	// P-521 is not accepted.
	k521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := k521.PublicKey.Bytes()
	jwk := json.RawMessage(`{"kty":"EC","crv":"P-521","x":"` + b64enc(raw[1:67]) + `","y":"` + b64enc(raw[67:]) + `"}`)
	h = map[string]any{"alg": "ES512", "nonce": c.getNonce(), "url": c.dir.NewAccount, "jwk": jwk}
	body = buildJWS(t, h, []byte(`{}`), func([]byte) []byte { return make([]byte, 132) })
	expectProblem(t, c.do(http.MethodPost, c.dir.NewAccount, body), ProbBadSignatureAlgorithm)
	h = map[string]any{"alg": algES256, "nonce": c.getNonce(), "url": c.dir.NewAccount, "jwk": jwk}
	body = buildJWS(t, h, []byte(`{}`), func([]byte) []byte { return make([]byte, 64) })
	expectProblem(t, c.do(http.MethodPost, c.dir.NewAccount, body), ProbBadPublicKey)

	// Point not on the curve.
	bad := json.RawMessage(`{"kty":"EC","crv":"P-256","x":"` + b64enc(make([]byte, 32)) + `","y":"` + b64enc(make([]byte, 32)) + `"}`)
	h = map[string]any{"alg": algES256, "nonce": c.getNonce(), "url": c.dir.NewAccount, "jwk": bad}
	body = buildJWS(t, h, []byte(`{}`), func([]byte) []byte { return make([]byte, 64) })
	expectProblem(t, c.do(http.MethodPost, c.dir.NewAccount, body), ProbBadPublicKey)
}

func TestWrongKeyAuthorization(t *testing.T) {
	env := newEnv(t, nil)
	c := env.newClient(algES256)
	c.register()
	orderURL, o := c.newOrder("wrong.example.com")
	a := c.getAuthz(o.Authorizations[0])
	ch := findChallenge(t, a, ChallengeHTTP01)
	env.site.set(ch.Token, ch.Token+".not-the-thumbprint")
	expectStatus(t, c.post(ch.URL, map[string]any{}), http.StatusOK)
	got := c.waitAuthz(o.Authorizations[0])
	mustf(t, got.Status == StatusInvalid, "authz status %s", got.Status)
	ch = findChallenge(t, got, ChallengeHTTP01)
	mustf(t, ch.Status == StatusInvalid && ch.Error != nil && ch.Error.Type == ProbUnauthorized, "challenge %+v", ch)
	mustf(t, c.getOrder(orderURL).Status == StatusInvalid, "order should be invalid")

	// Retrying a failed challenge does not restart validation.
	r := c.post(ch.URL, map[string]any{})
	expectStatus(t, r, http.StatusOK)
	var cj challengeJSON
	r.decode(t, &cj)
	mustf(t, cj.Status == StatusInvalid, "challenge restarted: %s", cj.Status)
}

func TestDNS01WrongDigest(t *testing.T) {
	env := newEnv(t, nil)
	c := env.newClient(algES256)
	c.register()
	_, o := c.newOrder("dnswrong.example.com")
	a := c.getAuthz(o.Authorizations[0])
	ch := findChallenge(t, a, ChallengeDNS01)
	env.dns.set("_acme-challenge.dnswrong.example.com", DNS01Digest(ch.Token+".wrong"))
	c.post(ch.URL, map[string]any{})
	mustf(t, c.waitAuthz(o.Authorizations[0]).Status == StatusInvalid, "authz should be invalid")
}

func TestChallengePOSTAsGETDoesNotTrigger(t *testing.T) {
	env := newEnv(t, nil)
	c := env.newClient(algES256)
	c.register()
	_, o := c.newOrder("peek.example.com")
	a := c.getAuthz(o.Authorizations[0])
	ch := findChallenge(t, a, ChallengeHTTP01)
	r := c.post(ch.URL, nil)
	expectStatus(t, r, http.StatusOK)
	mustf(t, strings.Contains(strings.Join(r.header.Values("Link"), ","), `rel="up"`), "missing up Link")
	mustf(t, c.getAuthz(o.Authorizations[0]).Status == StatusPending, "POST-as-GET triggered validation")
}

func TestFinalizeCSRChecks(t *testing.T) {
	env := newEnv(t, nil)
	c := env.newClient(algES256)
	c.register()
	orderURL, o := c.newOrder("csr.example.com", "www.csr.example.com")
	for _, az := range o.Authorizations {
		c.solve(c.getAuthz(az), ChallengeHTTP01)
		c.waitAuthz(az)
	}
	o = c.getOrder(orderURL)
	mustf(t, o.Status == StatusReady, "order %s", o.Status)
	k := genKey(t, algES256)

	cases := map[string][]byte{
		"extra SAN":      makeCSR(t, k, "", "csr.example.com", "www.csr.example.com", "evil.example.com"),
		"missing SAN":    makeCSR(t, k, "", "csr.example.com"),
		"CN not in SANs": makeCSR(t, k, "other.example.com", "csr.example.com", "www.csr.example.com"),
		"account key":    makeCSR(t, c.key, "", "csr.example.com", "www.csr.example.com"),
		"garbage":        []byte("not a csr"),
	}
	for name, csr := range cases {
		expectProblem(t, c.finalize(o, csr), ProbBadCSR)
		_ = name
	}
	// Tampered CSR signature.
	good := makeCSR(t, k, "", "csr.example.com", "www.csr.example.com")
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-3] ^= 0x01
	expectProblem(t, c.finalize(o, tampered), ProbBadCSR)

	// The order is still ready and a correct CSR succeeds; a second
	// finalize is then refused.
	expectStatus(t, c.finalize(o, good), http.StatusOK)
	expectProblem(t, c.finalize(o, good), ProbOrderNotReady)
}

func TestIssuerFailureInvalidatesOrder(t *testing.T) {
	env := newEnv(t, nil)
	env.issuer.fail = &Problem{Type: ProbRejectedIdentifier, Detail: "CA policy says no"}
	c := env.newClient(algES256)
	c.register()
	orderURL, o := c.newOrder("fail.example.com")
	c.solve(c.getAuthz(o.Authorizations[0]), ChallengeHTTP01)
	c.waitAuthz(o.Authorizations[0])
	o = c.getOrder(orderURL)
	expectProblem(t, c.finalize(o, makeCSR(t, genKey(t, algES256), "", "fail.example.com")), ProbRejectedIdentifier)
	o = c.getOrder(orderURL)
	mustf(t, o.Status == StatusInvalid && o.Error != nil, "order %+v", o)

	env.issuer.fail = errors.New("database password is hunter2")
	orderURL, o = c.newOrder("fail2.example.com")
	c.solve(c.getAuthz(o.Authorizations[0]), ChallengeHTTP01)
	c.waitAuthz(o.Authorizations[0])
	o = c.getOrder(orderURL)
	p := expectProblem(t, c.finalize(o, makeCSR(t, genKey(t, algES256), "", "fail2.example.com")), ProbServerInternal)
	mustf(t, !strings.Contains(p.Detail, "hunter2"), "internal error leaked: %q", p.Detail)
}

func TestEABRequiredAndBadMAC(t *testing.T) {
	key := []byte(strings.Repeat("e", 32))
	env := newEnv(t, func(cfg *Config) {
		cfg.RequireEAB = true
		cfg.EABKeys = eabMap{"kid-1": {key, "tenant"}, "short": {[]byte("tooshort"), "tenant"}}
	})
	c := env.newClient(algES256)
	expectProblem(t, c.post(c.dir.NewAccount, map[string]any{"termsOfServiceAgreed": true}), ProbExternalAccountRequired)

	// Bad MAC.
	bad := eabJWS(t, "kid-1", []byte(strings.Repeat("x", 32)), c.dir.NewAccount, c.key.Public())
	expectProblem(t, c.post(c.dir.NewAccount, map[string]any{"termsOfServiceAgreed": true, "externalAccountBinding": bad}), ProbUnauthorized)
	// Unknown kid.
	unk := eabJWS(t, "kid-2", key, c.dir.NewAccount, c.key.Public())
	expectProblem(t, c.post(c.dir.NewAccount, map[string]any{"termsOfServiceAgreed": true, "externalAccountBinding": unk}), ProbUnauthorized)
	// Binding a different key than the account key.
	other := genKey(t, algES256)
	wrongKey := eabJWS(t, "kid-1", key, c.dir.NewAccount, other.Public())
	expectProblem(t, c.post(c.dir.NewAccount, map[string]any{"termsOfServiceAgreed": true, "externalAccountBinding": wrongKey}), ProbUnauthorized)
	// Wrong url inside the binding.
	wrongURL := eabJWS(t, "kid-1", key, c.dir.NewOrder, c.key.Public())
	expectProblem(t, c.post(c.dir.NewAccount, map[string]any{"termsOfServiceAgreed": true, "externalAccountBinding": wrongURL}), ProbUnauthorized)
	// Key shorter than 256 bits is refused.
	// (The client signs with a full-length key: HMAC with a sub-112-bit key
	// panics in FIPS-only mode. The server must refuse before using the
	// short stored key at all.)
	short := eabJWS(t, "short", key, c.dir.NewAccount, c.key.Public())
	expectProblem(t, c.post(c.dir.NewAccount, map[string]any{"termsOfServiceAgreed": true, "externalAccountBinding": short}), ProbServerInternal)
	// Non-MAC EAB algorithm.
	asym := json.RawMessage(buildJWS(t, map[string]any{"alg": algES256, "kid": "kid-1", "url": c.dir.NewAccount}, jwkJSON(t, c.key.Public()),
		func(in []byte) []byte { return signWith(t, c.key, algES256, in) }))
	expectProblem(t, c.post(c.dir.NewAccount, map[string]any{"termsOfServiceAgreed": true, "externalAccountBinding": asym}), ProbBadSignatureAlgorithm)

	// Correct binding works.
	good := eabJWS(t, "kid-1", key, c.dir.NewAccount, c.key.Public())
	expectStatus(t, c.post(c.dir.NewAccount, map[string]any{"termsOfServiceAgreed": true, "externalAccountBinding": good}), http.StatusCreated)
}

func TestNewOrderIdentifierChecks(t *testing.T) {
	env := newEnv(t, func(cfg *Config) { cfg.MaxIdentifiers = 3; cfg.MaxPendingOrders = 2 })
	c := env.newClient(algES256)
	c.register()
	post := func(ids ...Identifier) *response {
		return c.post(c.dir.NewOrder, map[string]any{"identifiers": ids})
	}
	expectProblem(t, post(), ProbMalformed)
	expectProblem(t, post(identifiers("a.example.com", "b.example.com", "c.example.com", "d.example.com")...), ProbRejectedIdentifier)
	expectProblem(t, post(Identifier{"email", "a@example.com"}), ProbUnsupportedIdentifier)
	for _, bad := range []string{"*.*.example.com", "foo.*.example.com", "-a.example.com", "a..example.com", "exa mple.com", "bücher.example", "example.123", "*.192.0.2.1"} {
		expectProblem(t, post(Identifier{IdentifierDNS, bad}), ProbRejectedIdentifier)
	}
	expectProblem(t, post(Identifier{IdentifierIP, "not-an-ip"}), ProbRejectedIdentifier)
	expectProblem(t, post(Identifier{IdentifierDNS, "192.0.2.1"}), ProbRejectedIdentifier)

	// Duplicates collapse after normalization.
	_, o := c.newOrder("Dup.Example.com", "dup.example.com")
	mustf(t, len(o.Identifiers) == 1, "identifiers %v", o.Identifiers)
	c.newOrder("second.example.com")
	expectProblem(t, post(identifiers("third.example.com")...), ProbRateLimited)
}

func TestHTTP01RedirectPolicy(t *testing.T) {
	mk := func(raw string) *http.Request {
		u, _ := url.Parse(raw)
		return &http.Request{URL: u}
	}
	via := []*http.Request{mk("http://a.example/")}
	for _, ok := range []string{"http://b.example/x", "http://b.example:80/x", "https://b.example/x", "https://b.example:443/x"} {
		mustf(t, http01CheckRedirect(mk(ok), via) == nil, "redirect to %s refused", ok)
	}
	for _, bad := range []string{"http://b.example:8080/x", "https://b.example:80/x", "ftp://b.example/x", "http://b.example:443/x"} {
		mustf(t, http01CheckRedirect(mk(bad), via) != nil, "redirect to %s allowed", bad)
	}
	many := make([]*http.Request, 11)
	mustf(t, http01CheckRedirect(mk("http://b.example/"), many) != nil, "11th redirect allowed")
	mustf(t, http01CheckRedirect(mk("http://b.example/"), many[:10]) == nil, "10th redirect refused")

	// Default client verifies TLS.
	tr := DefaultHTTP01Client().Transport.(*http.Transport)
	mustf(t, tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify, "default client skips TLS verification")
}

func TestHTTP01BodyLimit(t *testing.T) {
	env := newEnv(t, nil)
	c := env.newClient(algES256)
	c.register()
	_, o := c.newOrder("big.example.com")
	a := c.getAuthz(o.Authorizations[0])
	ch := findChallenge(t, a, ChallengeHTTP01)
	env.site.set(ch.Token, ch.Token+"."+c.thumbprint()+strings.Repeat(" ", 2048))
	c.post(ch.URL, map[string]any{})
	mustf(t, c.waitAuthz(o.Authorizations[0]).Status == StatusInvalid, "oversized body accepted")
}

func TestSuffixPolicy(t *testing.T) {
	p := SuffixPolicy{Suffixes: map[string][]string{"t": {"example.com"}}}
	ctx := context.Background()
	for _, ok := range []string{"example.com", "a.example.com", "*.example.com"} {
		mustf(t, p.Allow(ctx, "t", Identifier{IdentifierDNS, ok}) == nil, "%s refused", ok)
	}
	for _, bad := range []string{"badexample.com", "example.org"} {
		mustf(t, p.Allow(ctx, "t", Identifier{IdentifierDNS, bad}) != nil, "%s allowed", bad)
	}
	mustf(t, p.Allow(ctx, "", Identifier{IdentifierDNS, "a.example.com"}) != nil, "unbound account allowed")
	mustf(t, p.Allow(ctx, "t", Identifier{IdentifierIP, "192.0.2.1"}) != nil, "IP allowed without prefixes")
}

// RFC 7638 §3.1 example.
func TestThumbprintRFC7638(t *testing.T) {
	raw := []byte(`{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}`)
	pub, prob := parseJWK(raw)
	if prob != nil {
		t.Fatal(prob)
	}
	tp, err := Thumbprint(pub)
	mustf(t, err == nil && tp == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", "thumbprint %s %v", tp, err)
}
