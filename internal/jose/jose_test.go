package jose

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	rsaOnce sync.Once
	rsaKey  *rsa.PrivateKey
)

func testRSAKey(t testing.TB) *rsa.PrivateKey {
	rsaOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		rsaKey = k
	})
	return rsaKey
}

func mustEC(t testing.TB, c elliptic.Curve) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testSigners(t *testing.T) []Signer {
	t.Helper()
	var out []Signer
	for _, c := range []struct {
		k   crypto.Signer
		alg string
	}{{mustEC(t, elliptic.P256()), ES256}, {mustEC(t, elliptic.P384()), ES384}, {testRSAKey(t), RS256}, {testRSAKey(t), PS256}} {
		s, err := NewLocalSigner(c.k, c.alg, "")
		if err != nil {
			t.Fatalf("%s: %v", c.alg, err)
		}
		out = append(out, s)
	}
	return out
}

func TestSignVerifyRoundTrip(t *testing.T) {
	ctx := context.Background()
	for _, s := range testSigners(t) {
		t.Run(s.Alg(), func(t *testing.T) {
			tok, err := SignJWT(ctx, s, map[string]any{"sub": "x", "exp": time.Now().Add(time.Minute).Unix()})
			if err != nil {
				t.Fatal(err)
			}
			set := &JWKSet{Keys: []JWK{NewJWK(s)}}
			data, _ := json.Marshal(set)
			parsed, err := ParseJWKSet(data)
			if err != nil || len(parsed.Keys) != 1 {
				t.Fatalf("parse: %v", err)
			}
			j, err := Verify(ctx, tok, parsed)
			if err != nil {
				t.Fatal(err)
			}
			if j.Header.Kid != s.KeyID() || j.Header.Typ != "JWT" {
				t.Fatalf("header %+v", j.Header)
			}
			c, err := ParseClaims(j.Payload)
			if err != nil {
				t.Fatal(err)
			}
			if err := (Validator{}).Validate(c); err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(tok, ".")
			parts[1] = b64.EncodeToString([]byte(`{"sub":"y"}`))
			if _, err := Verify(ctx, strings.Join(parts, "."), parsed); !errors.Is(err, ErrSignature) {
				t.Fatalf("tampered: %v", err)
			}
			other := ES256
			if s.Alg() == ES256 {
				other = RS256
			}
			if _, err := Verify(ctx, tok, parsed, other); !errors.Is(err, ErrUnsupportedAlg) {
				t.Fatalf("alg restriction: %v", err)
			}
		})
	}
}

func TestDisallowedAlgs(t *testing.T) {
	ctx := context.Background()
	rk := testRSAKey(t)
	set := &JWKSet{Keys: []JWK{{Key: &rk.PublicKey, KeyID: "k"}}}
	payload := b64.EncodeToString([]byte(`{"exp":9999999999}`))
	der, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	for _, alg := range []string{"none", "None", "HS256", "HS384", "HS512", "EdDSA", "RS384", "ES512", "PS512", ""} {
		hdr := b64.EncodeToString([]byte(`{"alg":"` + alg + `","kid":"k"}`))
		input := hdr + "." + payload
		// Key confusion: the RSA public key used as an HMAC secret.
		m := hmac.New(sha256.New, der)
		m.Write([]byte(input))
		for _, tok := range []string{input + ".", input + "." + b64.EncodeToString(m.Sum(nil))} {
			if _, err := Verify(ctx, tok, set); err == nil {
				t.Fatalf("alg %q accepted", alg)
			}
		}
	}
}

func TestMalformed(t *testing.T) {
	for _, tok := range []string{"", "a.b", "a.b.c.d", "!!.e30.AA", "e30.e30.AA", "eyJhbGciOiJFUzI1NiJ9.e30=.AA",
		"eyJhbGciOiJFUzI1NiJ9.e30.",
		b64.EncodeToString([]byte(`{"alg":"ES256","crit":["exp"]}`)) + ".e30.AA"} {
		if _, err := ParseCompact(tok); err == nil {
			t.Fatalf("accepted %q", tok)
		}
	}
}

func TestKeyMismatch(t *testing.T) {
	p256 := mustEC(t, elliptic.P256())
	if _, err := NewLocalSigner(p256, ES384, ""); err == nil {
		t.Fatal("P-256 key accepted for ES384")
	}
	if _, err := NewLocalSigner(p256, RS256, ""); err == nil {
		t.Fatal("EC key accepted for RS256")
	}
	if _, err := NewLocalSigner(p256, "HS256", ""); err == nil {
		t.Fatal("HS256 accepted")
	}
	small := &rsa.PublicKey{N: new(big.Int).SetBit(new(big.Int), 1023, 1), E: 65537}
	if err := CheckKey(RS256, small); err == nil {
		t.Fatal("1024-bit RSA accepted")
	}
}

// wrongKeySigner returns signatures from a different key than Public().
type wrongKeySigner struct {
	*LocalSigner
	other *LocalSigner
}

func (w wrongKeySigner) Sign(ctx context.Context, d []byte) ([]byte, error) {
	return w.other.Sign(ctx, d)
}

func TestSignFailsClosedOnKeyMismatch(t *testing.T) {
	sa, _ := NewLocalSigner(mustEC(t, elliptic.P256()), ES256, "a")
	sb, _ := NewLocalSigner(mustEC(t, elliptic.P256()), ES256, "b")
	if _, err := SignJWT(context.Background(), wrongKeySigner{sa, sb}, map[string]any{}); err == nil {
		t.Fatal("mismatched signer accepted")
	}
}

// rawECSigner returns R||S instead of DER, like some KMS APIs.
type rawECSigner struct{ *LocalSigner }

func (r rawECSigner) Sign(ctx context.Context, d []byte) ([]byte, error) {
	der, err := r.LocalSigner.Sign(ctx, d)
	if err != nil {
		return nil, err
	}
	return normalizeECDSA(der, 32)
}

func TestRawECDSASignatureAccepted(t *testing.T) {
	s, _ := NewLocalSigner(mustEC(t, elliptic.P256()), ES256, "")
	tok, err := SignJWT(context.Background(), rawECSigner{s}, map[string]any{"exp": 1})
	if err != nil {
		t.Fatal(err)
	}
	j, _ := ParseCompact(tok)
	if err := j.Verify(s.Public()); err != nil {
		t.Fatal(err)
	}
}

func TestThumbprintRFC7638(t *testing.T) {
	// RFC 7638 section 3.1 example.
	const n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	var k JWK
	if err := json.Unmarshal([]byte(`{"kty":"RSA","n":"`+n+`","e":"AQAB","alg":"RS256","kid":"2011-04-29"}`), &k); err != nil {
		t.Fatal(err)
	}
	tp, err := k.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if tp != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("thumbprint %s", tp)
	}
}

func TestJWKRejects(t *testing.T) {
	for _, s := range []string{
		`{"kty":"oct","k":"AAAA"}`,
		`{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
		`{"kty":"EC","crv":"P-521","x":"AA","y":"AA"}`,
		`{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`,
		`{"kty":"RSA","n":"AQAB","e":"AQAB"}`,
	} {
		var k JWK
		if err := json.Unmarshal([]byte(s), &k); err == nil {
			t.Fatalf("accepted %s", s)
		}
	}
	p := mustEC(t, elliptic.P256())
	data, _ := json.Marshal(JWK{Key: &p.PublicKey})
	var m map[string]any
	json.Unmarshal(data, &m)
	m["d"] = "AAAA"
	data, _ = json.Marshal(m)
	var k JWK
	if err := json.Unmarshal(data, &k); err == nil {
		t.Fatal("private JWK accepted")
	}
	set, err := ParseJWKSet([]byte(`{"keys":[` + string(data) + `,{"kty":"oct","k":"AA"}]}`))
	if err != nil || len(set.Keys) != 0 {
		t.Fatalf("set: %v", err)
	}
}

func TestLookup(t *testing.T) {
	a, b := mustEC(t, elliptic.P256()), mustEC(t, elliptic.P256())
	set := &JWKSet{Keys: []JWK{{Key: &a.PublicKey, KeyID: "a"}, {Key: &b.PublicKey, KeyID: "b"}, {Key: &testRSAKey(t).PublicKey, KeyID: "r", Alg: RS256}}}
	if k, err := set.Lookup("b", ES256); err != nil || k.KeyID != "b" {
		t.Fatal(err)
	}
	if _, err := set.Lookup("", ES256); !errors.Is(err, ErrKeyNotFound) {
		t.Fatal("ambiguous empty kid accepted")
	}
	if k, err := set.Lookup("", RS256); err != nil || k.KeyID != "r" {
		t.Fatal(err)
	}
	if _, err := set.Lookup("r", PS256); err == nil {
		t.Fatal("JWK alg ignored")
	}
	if _, err := set.Lookup("a", ES384); err == nil {
		t.Fatal("curve mismatch accepted")
	}
}

func TestValidator(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	base := func() Claims {
		return Claims{"iss": "https://i", "aud": []any{"a", "b"}, "exp": json.Number("1700000060"), "iat": json.Number("1700000000"), "nbf": json.Number("1700000000"), "sub": "s"}
	}
	v := Validator{Issuer: "https://i", Audience: "b", Now: func() time.Time { return now }, Leeway: 30 * time.Second, Required: []string{"sub"}, RequireIssuedAt: true}
	if err := v.Validate(base()); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		mut  func(Claims)
		want error
	}{
		{"iss", func(c Claims) { c["iss"] = "https://x" }, ErrIssuer},
		{"aud", func(c Claims) { c["aud"] = "c" }, ErrAudience},
		{"aud type", func(c Claims) { c["aud"] = json.Number("1") }, ErrClaimInvalid},
		{"expired", func(c Claims) { c["exp"] = json.Number("1699999969") }, ErrExpired},
		{"no exp", func(c Claims) { delete(c, "exp") }, ErrClaimMissing},
		{"nbf", func(c Claims) { c["nbf"] = json.Number("1700000031") }, ErrNotYetValid},
		{"iat future", func(c Claims) { c["iat"] = json.Number("1700000031") }, ErrIssuedInFuture},
		{"no iat", func(c Claims) { delete(c, "iat") }, ErrClaimMissing},
		{"no sub", func(c Claims) { delete(c, "sub") }, ErrClaimMissing},
		{"exp string", func(c Claims) { c["exp"] = "soon" }, ErrClaimInvalid},
	}
	for _, tc := range cases {
		c := base()
		tc.mut(c)
		if err := v.Validate(c); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v want %v", tc.name, err, tc.want)
		}
	}
	c := base()
	c["exp"] = json.Number("1699999990") // expired, but within leeway
	if err := v.Validate(c); err != nil {
		t.Fatal(err)
	}
	c = base()
	c["aud"] = "b"
	if err := v.Validate(c); err != nil {
		t.Fatal(err)
	}
}
