package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/fips140"
	"encoding/json"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDirectoryAndNonce(t *testing.T) {
	env := newEnv(t, nil)
	c := env.newClient(algES256)
	mustf(t, c.dir.NewNonce == env.base+"/new-nonce", "newNonce %q", c.dir.NewNonce)
	mustf(t, c.dir.KeyChange == env.base+"/key-change", "keyChange %q", c.dir.KeyChange)
	mustf(t, c.dir.Meta.TermsOfService == "https://example.test/tos", "tos %q", c.dir.Meta.TermsOfService)
	mustf(t, !c.dir.Meta.ExternalAccountRequired, "EAB should not be required")

	head := c.do(http.MethodHead, c.dir.NewNonce, nil)
	expectStatus(t, head, http.StatusOK)
	get := c.do(http.MethodGet, c.dir.NewNonce, nil)
	expectStatus(t, get, http.StatusNoContent)
	for _, r := range []*response{head, get} {
		mustf(t, r.header.Get("Replay-Nonce") != "", "missing Replay-Nonce")
		mustf(t, r.header.Get("Cache-Control") == "no-store", "missing Cache-Control: no-store")
		mustf(t, slices.Contains(r.header.Values("Link"), `<`+env.base+`/directory>;rel="index"`), "missing index Link: %v", r.header.Values("Link"))
	}
	mustf(t, head.header.Get("Replay-Nonce") != get.header.Get("Replay-Nonce"), "nonces repeat")
}

// TestFullFlow drives directory → nonce → newAccount → newOrder → authz →
// http-01 and dns-01 challenges → finalize → download → revoke.
func TestFullFlow(t *testing.T) {
	env := newEnv(t, nil)
	c := env.newClient(algES256)
	c.register()

	orderURL, o := c.newOrder("www.example.com", "API.example.com")
	mustf(t, o.Status == StatusPending, "new order status %s", o.Status)
	mustf(t, len(o.Authorizations) == 2, "authorizations %v", o.Authorizations)
	mustf(t, slices.Contains(o.Identifiers, Identifier{IdentifierDNS, "api.example.com"}), "identifiers not normalized: %v", o.Identifiers)

	// Finalizing now is premature.
	resp := c.finalize(o, makeCSR(t, genKey(t, algES256), "", "www.example.com", "api.example.com"))
	expectProblem(t, resp, ProbOrderNotReady)

	for i, az := range o.Authorizations {
		a := c.getAuthz(az)
		mustf(t, a.Status == StatusPending, "authz status %s", a.Status)
		mustf(t, len(a.Challenges) == 2, "challenges %v", a.Challenges)
		typ := ChallengeHTTP01
		if i == 1 {
			typ = ChallengeDNS01
		}
		c.solve(a, typ)
		got := c.waitAuthz(az)
		mustf(t, got.Status == StatusValid, "authz %s status %s: %+v", a.Identifier.Value, got.Status, got.Challenges)
		ch := findChallenge(t, got, typ)
		mustf(t, ch.Status == StatusValid && ch.Validated != "", "challenge %+v", ch)
	}
	o = c.getOrder(orderURL)
	mustf(t, o.Status == StatusReady, "order status %s", o.Status)

	certKey := genKey(t, algES256)
	resp = c.finalize(o, makeCSR(t, certKey, "www.example.com", "www.example.com", "api.example.com"))
	expectStatus(t, resp, http.StatusOK)
	resp.decode(t, &o)
	mustf(t, o.Status == StatusValid && o.Certificate != "", "order after finalize %+v", o)

	cr := c.post(o.Certificate, nil)
	expectStatus(t, cr, http.StatusOK)
	mustf(t, cr.header.Get("Content-Type") == "application/pem-certificate-chain", "content type %q", cr.header.Get("Content-Type"))

	// Issuer received the order's identifiers and the bound account ref.
	req := env.issuer.reqs[0]
	mustf(t, len(req.Identifiers) == 2 && req.AccountRef == "", "issue request %+v", req)

	// Download as another account is refused.
	other := env.newClient(algES256)
	other.register()
	expectProblem(t, other.post(o.Certificate, nil), ProbUnauthorized)
	expectProblem(t, other.post(orderURL, nil), ProbUnauthorized)

	// Revoke with the account key.
	cert := parseChainLeaf(t, cr.body)
	expectStatus(t, c.revoke(cert, 4), http.StatusOK)
	mustf(t, env.issuer.revoked[cert.SerialNumber.Text(16)] == 4, "issuer did not revoke")
	expectProblem(t, c.revoke(cert, 4), ProbAlreadyRevoked)

	// Account order list.
	var acct accountJSON
	ar := c.post(c.kid, nil)
	expectStatus(t, ar, http.StatusOK)
	ar.decode(t, &acct)
	lr := c.post(acct.Orders, nil)
	expectStatus(t, lr, http.StatusOK)
	var list struct{ Orders []string }
	lr.decode(t, &list)
	mustf(t, len(list.Orders) == 1 && list.Orders[0] == orderURL, "orders list %v", list.Orders)
}

func TestAccountKeyAlgorithms(t *testing.T) {
	for _, alg := range []string{algES256, algES384, algRS256, algPS256, algEdDSA} {
		t.Run(alg, func(t *testing.T) {
			env := newEnv(t, nil)
			c := env.newClient(alg)
			c.register()
			c.obtain(ChallengeHTTP01, "alg.example.com")
		})
	}
}

func TestWildcardRequiresDNS01(t *testing.T) {
	env := newEnv(t, nil)
	c := env.newClient(algES256)
	c.register()
	_, o := c.newOrder("*.example.com")
	a := c.getAuthz(o.Authorizations[0])
	mustf(t, a.Wildcard, "authz should be marked wildcard")
	mustf(t, a.Identifier == Identifier{IdentifierDNS, "example.com"}, "authz identifier %v", a.Identifier)
	for _, ch := range a.Challenges {
		mustf(t, ch.Type != ChallengeHTTP01, "wildcard authz offers http-01")
	}
	// The http-01 validator itself refuses wildcards too.
	err := HTTP01Validator{}.Validate(context.Background(), Identifier{IdentifierDNS, "*.example.com"}, "t", "t.k")
	mustf(t, err != nil, "http-01 validated a wildcard")

	leaf, _, _ := c.obtain(ChallengeDNS01, "*.example.com", "example.com")
	mustf(t, slices.Contains(leaf.DNSNames, "*.example.com"), "leaf names %v", leaf.DNSNames)
}

func TestIPIdentifierUsesHTTP01Only(t *testing.T) {
	env := newEnv(t, nil)
	c := env.newClient(algES256)
	c.register()
	_, o := c.newOrder("192.0.2.10")
	a := c.getAuthz(o.Authorizations[0])
	mustf(t, len(a.Challenges) == 1 && a.Challenges[0].Type == ChallengeHTTP01, "challenges %+v", a.Challenges)
	leaf, _, _ := c.obtain(ChallengeHTTP01, "192.0.2.10")
	mustf(t, len(leaf.IPAddresses) == 1 && leaf.IPAddresses[0].Equal(net.ParseIP("192.0.2.10")), "leaf IPs %v", leaf.IPAddresses)
}

func TestRevokeWithCertificateKey(t *testing.T) {
	env := newEnv(t, nil)
	c := env.newClient(algES256)
	c.register()
	leaf, certKey, _ := c.obtain(ChallengeHTTP01, "key.example.com")

	// Anyone holding the certificate key may revoke, signing with jwk.
	h := map[string]any{"alg": algES256, "nonce": c.getNonce(), "url": c.dir.RevokeCert, "jwk": jwkJSON(t, certKey.Public())}
	body := buildJWS(t, h, marshalPayload(t, map[string]any{"certificate": b64enc(leaf.Raw)}), func(in []byte) []byte {
		return signWith(t, certKey, algES256, in)
	})
	expectStatus(t, c.do(http.MethodPost, c.dir.RevokeCert, body), http.StatusOK)

	// An unrelated key signing with jwk is refused.
	leaf2, _, _ := c.obtain(ChallengeHTTP01, "key3.example.com")
	stranger := genKey(t, algES256)
	h = map[string]any{"alg": algES256, "nonce": c.getNonce(), "url": c.dir.RevokeCert, "jwk": jwkJSON(t, stranger.Public())}
	body = buildJWS(t, h, marshalPayload(t, map[string]any{"certificate": b64enc(leaf2.Raw)}), func(in []byte) []byte {
		return signWith(t, stranger, algES256, in)
	})
	expectProblem(t, c.do(http.MethodPost, c.dir.RevokeCert, body), ProbUnauthorized)
}

func TestRevokeByAuthorizedOtherAccount(t *testing.T) {
	env := newEnv(t, nil)
	owner := env.newClient(algES256)
	owner.register()
	leaf, _, _ := owner.obtain(ChallengeHTTP01, "shared.example.com")

	unrelated := env.newClient(algES256)
	unrelated.register()
	expectProblem(t, unrelated.revoke(leaf, 0), ProbUnauthorized)

	// After proving control of the name, the other account may revoke.
	unrelated.obtain(ChallengeDNS01, "shared.example.com")
	expectStatus(t, unrelated.revoke(leaf, 1), http.StatusOK)
}

func TestKeyRollover(t *testing.T) {
	env := newEnv(t, nil)
	c := env.newClient(algES256)
	c.register()
	oldKey := c.key
	newKey := genKey(t, algES384)

	inner := buildJWS(t, map[string]any{"alg": algES384, "url": c.dir.KeyChange, "jwk": jwkJSON(t, newKey.Public())},
		marshalPayload(t, map[string]any{"account": c.kid, "oldKey": jwkJSON(t, oldKey.Public())}),
		func(in []byte) []byte { return signWith(t, newKey, algES384, in) })
	expectStatus(t, c.post(c.dir.KeyChange, inner), http.StatusOK)

	// The old key no longer works; the new one does.
	if r := c.post(c.kid, nil); r.status == http.StatusOK {
		t.Fatal("old key still accepted after rollover")
	}
	c.key, c.alg = newKey, algES384
	expectStatus(t, c.post(c.kid, nil), http.StatusOK)

	// Rolling over to a key held by another account conflicts.
	other := env.newClient(algES256)
	other.register()
	inner = buildJWS(t, map[string]any{"alg": algES256, "url": c.dir.KeyChange, "jwk": jwkJSON(t, other.key.Public())},
		marshalPayload(t, map[string]any{"account": c.kid, "oldKey": jwkJSON(t, newKey.Public())}),
		func(in []byte) []byte { return signWith(t, other.key, algES256, in) })
	r := c.post(c.dir.KeyChange, inner)
	expectStatus(t, r, http.StatusConflict)
	mustf(t, r.header.Get("Location") == other.kid, "conflict Location %q", r.header.Get("Location"))
}

func TestAccountLookupUpdateDeactivate(t *testing.T) {
	env := newEnv(t, nil)
	c := env.newClient(algEdDSA)

	resp := c.post(c.dir.NewAccount, map[string]any{"onlyReturnExisting": true})
	expectProblem(t, resp, ProbAccountDoesNotExist)
	expectProblem(t, c.post(c.dir.NewAccount, map[string]any{}), ProbMalformed) // ToS not agreed
	expectProblem(t, c.post(c.dir.NewAccount, map[string]any{"termsOfServiceAgreed": true, "contact": []string{"tel:+1555"}}), ProbUnsupportedContact)
	c.register()

	kid := c.kid
	c.kid = ""
	resp = c.post(c.dir.NewAccount, map[string]any{"onlyReturnExisting": true})
	expectStatus(t, resp, http.StatusOK)
	mustf(t, resp.header.Get("Location") == kid, "existing account Location %q", resp.header.Get("Location"))
	c.kid = kid

	resp = c.post(c.kid, map[string]any{"contact": []string{"mailto:new@example.com"}})
	expectStatus(t, resp, http.StatusOK)
	var a accountJSON
	resp.decode(t, &a)
	mustf(t, len(a.Contact) == 1 && a.Contact[0] == "mailto:new@example.com", "contact %v", a.Contact)

	// Another account cannot update this one.
	other := env.newClient(algES256)
	other.register()
	expectProblem(t, other.post(c.kid, map[string]any{"status": "deactivated"}), ProbUnauthorized)

	resp = c.post(c.kid, map[string]any{"status": "deactivated"})
	expectStatus(t, resp, http.StatusOK)
	resp.decode(t, &a)
	mustf(t, a.Status == StatusDeactivated, "status %s", a.Status)
	expectProblem(t, c.post(c.dir.NewOrder, map[string]any{"identifiers": identifiers("x.example.com")}), ProbUnauthorized)
}

func TestAuthzDeactivationInvalidatesOrder(t *testing.T) {
	env := newEnv(t, nil)
	c := env.newClient(algES256)
	c.register()
	orderURL, o := c.newOrder("deact.example.com")
	resp := c.post(o.Authorizations[0], map[string]any{"status": "deactivated"})
	expectStatus(t, resp, http.StatusOK)
	o = c.getOrder(orderURL)
	mustf(t, o.Status == StatusInvalid, "order status %s", o.Status)
}

func TestOrderExpiry(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	env := newEnv(t, func(cfg *Config) { cfg.Clock = func() time.Time { return clock() } })
	c := env.newClient(algES256)
	c.register()
	orderURL, _ := c.newOrder("expire.example.com")
	later := now.Add(8 * 24 * time.Hour)
	clock = func() time.Time { return later }
	c.nonce = "" // nonces issued before the clock jump are now expired
	o := c.getOrder(orderURL)
	mustf(t, o.Status == StatusInvalid, "expired order status %s", o.Status)
}

func TestPolicyAndEABBinding(t *testing.T) {
	hmacKey := []byte(strings.Repeat("k", 32))
	env := newEnv(t, func(cfg *Config) {
		cfg.RequireEAB = true
		cfg.EABKeys = eabMap{"kid-1": {hmacKey, "tenant-a"}}
		cfg.Policy = SuffixPolicy{Suffixes: map[string][]string{"tenant-a": {"tenant-a.example"}}}
	})
	c := env.newClient(algES256)
	mustf(t, c.dir.Meta.ExternalAccountRequired, "directory should require EAB")
	resp := c.post(c.dir.NewAccount, map[string]any{
		"termsOfServiceAgreed":   true,
		"externalAccountBinding": eabJWS(t, "kid-1", hmacKey, c.dir.NewAccount, c.key.Public()),
	})
	expectStatus(t, resp, http.StatusCreated)
	c.kid = resp.header.Get("Location")

	acct, err := env.store.GetAccountByThumbprint(context.Background(), c.thumbprint())
	mustf(t, err == nil && acct.AccountRef == "tenant-a" && acct.EABKeyID == "kid-1", "account binding %+v %v", acct, err)

	c.obtain(ChallengeHTTP01, "www.tenant-a.example")
	mustf(t, env.issuer.reqs[0].AccountRef == "tenant-a", "issuer AccountRef %q", env.issuer.reqs[0].AccountRef)

	resp = c.post(c.dir.NewOrder, map[string]any{"identifiers": identifiers("www.tenant-b.example")})
	p := expectProblem(t, resp, ProbRejectedIdentifier)
	mustf(t, p.Identifier != nil && p.Identifier.Value == "www.tenant-b.example", "problem identifier %+v", p.Identifier)
}

type eabMap map[string]struct {
	key []byte
	ref string
}

func (m eabMap) Lookup(_ context.Context, kid string) ([]byte, string, error) {
	e, ok := m[kid]
	if !ok {
		return nil, "", ErrNotFound
	}
	return e.key, e.ref, nil
}

func eabJWS(t *testing.T, kid string, key []byte, url string, pub crypto.PublicKey) json.RawMessage {
	return buildJWS(t, map[string]any{"alg": "HS256", "kid": kid, "url": url}, jwkJSON(t, pub), func(in []byte) []byte {
		return hmacSHA256(key, in)
	})
}

func TestPrefixMount(t *testing.T) {
	// Hosts may strip the mount prefix before calling the handler.
	env := newEnv(t, nil)
	mux := http.NewServeMux()
	mux.Handle("/acme/", http.StripPrefix("/acme", env.srv))
	env.ts.Config.Handler = mux
	c := env.newClient(algES256)
	c.register()
	c.obtain(ChallengeDNS01, "strip.example.com")
}

func TestFIPSMode(t *testing.T) {
	// Informational: under GODEBUG=fips140=only this reports true and the
	// whole suite, including Ed25519 accounts, runs inside the module.
	t.Logf("crypto/fips140.Enabled() = %v", fips140.Enabled())
}

func TestConcurrentFinalizeIssuesOnce(t *testing.T) {
	env := newEnv(t, nil)
	c := env.newClient(algES256)
	c.register()
	orderURL, o := c.newOrder("race.example.com")
	c.solve(c.getAuthz(o.Authorizations[0]), ChallengeHTTP01)
	c.waitAuthz(o.Authorizations[0])
	o = c.getOrder(orderURL)
	csr := makeCSR(t, genKey(t, algES256), "", "race.example.com")

	const n = 8
	bodies := make([][]byte, n)
	for i := range bodies {
		bodies[i] = c.signed(o.Finalize, map[string]string{"csr": b64enc(csr)})
	}
	var wg sync.WaitGroup
	statuses := make([]int, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPost, o.Finalize, bytes.NewReader(bodies[i]))
			req.Header.Set("Content-Type", "application/jose+json")
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				statuses[i] = resp.StatusCode
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	ok := 0
	for _, s := range statuses {
		if s == http.StatusOK {
			ok++
		}
	}
	mustf(t, ok == 1, "%d finalize requests succeeded (%v)", ok, statuses)
	env.issuer.mu.Lock()
	defer env.issuer.mu.Unlock()
	mustf(t, len(env.issuer.reqs) == 1, "issuer called %d times", len(env.issuer.reqs))
}
