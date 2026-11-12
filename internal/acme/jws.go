package acme

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash"
	"math/big"
	"net/http"
	"strings"
)

// Supported outer-JWS algorithms. All are FIPS 140-3 approved: ECDSA on
// P-256/P-384 (FIPS 186-5), RSA PKCS#1 v1.5 and PSS with SHA-256 and
// moduli of at least 2048 bits, and Ed25519 (FIPS 186-5).
const (
	algES256 = "ES256"
	algES384 = "ES384"
	algRS256 = "RS256"
	algPS256 = "PS256"
	algEdDSA = "EdDSA"
)

// SupportedAlgorithms lists the JWS algorithms accepted for account keys.
var SupportedAlgorithms = []string{algES256, algES384, algRS256, algPS256, algEdDSA}

const (
	minRSABits = 2048
	maxRSABits = 8192
	// minEABKeyLen is the minimum EAB HMAC key length (256 bits).
	minEABKeyLen = 32
)

var b64 = base64.RawURLEncoding.Strict()

func b64enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// flattenedJWS is the RFC 7515 §7.2.2 flattened JSON serialization. The
// unprotected "header" member and the general serialization are rejected by
// decoding with DisallowUnknownFields (RFC 8555 §6.2).
type flattenedJWS struct {
	Protected string  `json:"protected"`
	Payload   *string `json:"payload"`
	Signature string  `json:"signature"`
}

type protectedHeader struct {
	Alg   string          `json:"alg"`
	Nonce string          `json:"nonce"`
	URL   string          `json:"url"`
	JWK   json.RawMessage `json:"jwk"`
	KID   string          `json:"kid"`
	Crit  json.RawMessage `json:"crit"`
	B64   json.RawMessage `json:"b64"`
}

// parsedJWS is a syntactically valid JWS whose signature is not yet checked.
type parsedJWS struct {
	header       protectedHeader
	rawHeader    []byte
	payload      []byte
	signature    []byte
	signingInput []byte
}

func parseJWS(body []byte) (*parsedJWS, *Problem) {
	var f flattenedJWS
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, malformed("request body is not a flattened JWS: %v", err)
	}
	if dec.More() {
		return nil, malformed("trailing data after JWS")
	}
	// An empty signature is syntactically allowed here so that alg "none"
	// is reported as badSignatureAlgorithm; verification rejects it later.
	if f.Protected == "" || f.Payload == nil {
		return nil, malformed("JWS must have protected, payload and signature members")
	}
	rawHeader, err := b64.DecodeString(f.Protected)
	if err != nil {
		return nil, malformed("protected header is not base64url")
	}
	payload, err := b64.DecodeString(*f.Payload)
	if err != nil {
		return nil, malformed("payload is not base64url")
	}
	sig, err := b64.DecodeString(f.Signature)
	if err != nil {
		return nil, malformed("signature is not base64url")
	}
	var h protectedHeader
	if err := json.Unmarshal(rawHeader, &h); err != nil {
		return nil, malformed("protected header is not a JSON object")
	}
	if len(h.Crit) > 0 || len(h.B64) > 0 {
		return nil, malformed("crit and b64 header parameters are not supported")
	}
	return &parsedJWS{
		header:       h,
		rawHeader:    rawHeader,
		payload:      payload,
		signature:    sig,
		signingInput: []byte(f.Protected + "." + *f.Payload),
	}, nil
}

func badSigAlg(format string, args ...any) *Problem {
	p := newProblem(ProbBadSignatureAlgorithm, http.StatusBadRequest, format, args...)
	p.Algorithms = SupportedAlgorithms
	return p
}

func badPublicKey(format string, args ...any) *Problem {
	return newProblem(ProbBadPublicKey, http.StatusBadRequest, format, args...)
}

// checkOuterAlg rejects "none", MAC algorithms and anything unsupported.
func checkOuterAlg(alg string) *Problem {
	switch alg {
	case algES256, algES384, algRS256, algPS256, algEdDSA:
		return nil
	case "":
		return malformed("JWS protected header has no alg")
	default:
		return badSigAlg("JWS algorithm %q is not supported", alg)
	}
}

type jsonWebKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n"`
	E   string `json:"e"`
	D   string `json:"d"`
}

// parseJWK parses a public JWK and enforces this server's key policy.
func parseJWK(raw []byte) (crypto.PublicKey, *Problem) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, malformed("missing JWK")
	}
	var k jsonWebKey
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, malformed("JWK is not a JSON object")
	}
	if k.D != "" {
		return nil, badPublicKey("JWK contains private key material")
	}
	switch k.Kty {
	case "EC":
		var curve elliptic.Curve
		var size int
		switch k.Crv {
		case "P-256":
			curve, size = elliptic.P256(), 32
		case "P-384":
			curve, size = elliptic.P384(), 48
		default:
			return nil, badPublicKey("unsupported EC curve %q (want P-256 or P-384)", k.Crv)
		}
		x, err1 := b64.DecodeString(k.X)
		y, err2 := b64.DecodeString(k.Y)
		if err1 != nil || err2 != nil || len(x) != size || len(y) != size {
			return nil, badPublicKey("invalid EC point encoding")
		}
		pt := append(append([]byte{4}, x...), y...)
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, pt)
		if err != nil {
			return nil, badPublicKey("invalid EC point: %v", err)
		}
		return pub, nil
	case "RSA":
		n, err1 := b64.DecodeString(k.N)
		e, err2 := b64.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(n) == 0 || len(e) == 0 || len(e) > 4 {
			return nil, badPublicKey("invalid RSA key encoding")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n)}
		ev := new(big.Int).SetBytes(e)
		if !ev.IsInt64() || ev.Int64() <= 65536 || ev.Int64() > 1<<31-1 || ev.Bit(0) == 0 {
			return nil, badPublicKey("unsupported RSA public exponent")
		}
		pub.E = int(ev.Int64())
		if bits := pub.N.BitLen(); bits < minRSABits || bits > maxRSABits {
			return nil, badPublicKey("RSA key is %d bits; must be between %d and %d", bits, minRSABits, maxRSABits)
		}
		if pub.N.Bit(0) == 0 {
			return nil, badPublicKey("RSA modulus is even")
		}
		return pub, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, badPublicKey("unsupported OKP curve %q (want Ed25519)", k.Crv)
		}
		x, err := b64.DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, badPublicKey("invalid Ed25519 key")
		}
		return ed25519.PublicKey(x), nil
	default:
		return nil, badPublicKey("unsupported key type %q", k.Kty)
	}
}

// canonicalJWK returns the RFC 7638 thumbprint input for pub: the required
// members only, in lexicographic order, no whitespace.
func canonicalJWK(pub crypto.PublicKey) ([]byte, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		raw, err := k.Bytes()
		if err != nil {
			return nil, err
		}
		size := (len(raw) - 1) / 2
		crv := "P-256"
		if k.Curve == elliptic.P384() {
			crv = "P-384"
		} else if k.Curve != elliptic.P256() {
			return nil, errors.New("unsupported curve")
		}
		return []byte(`{"crv":"` + crv + `","kty":"EC","x":"` + b64enc(raw[1:1+size]) + `","y":"` + b64enc(raw[1+size:]) + `"}`), nil
	case *rsa.PublicKey:
		e := big.NewInt(int64(k.E)).Bytes()
		return []byte(`{"e":"` + b64enc(e) + `","kty":"RSA","n":"` + b64enc(k.N.Bytes()) + `"}`), nil
	case ed25519.PublicKey:
		return []byte(`{"crv":"Ed25519","kty":"OKP","x":"` + b64enc(k) + `"}`), nil
	default:
		return nil, errors.New("unsupported key type")
	}
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint of pub, base64url.
func Thumbprint(pub crypto.PublicKey) (string, error) {
	c, err := canonicalJWK(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return b64enc(sum[:]), nil
}

// keyAuthorization computes token || '.' || thumbprint (RFC 8555 §8.1).
func keyAuthorization(token, thumbprint string) string { return token + "." + thumbprint }

// algMatchesKey reports whether alg may be used with pub.
func algMatchesKey(alg string, pub crypto.PublicKey) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return (alg == algES256 && k.Curve == elliptic.P256()) || (alg == algES384 && k.Curve == elliptic.P384())
	case *rsa.PublicKey:
		return alg == algRS256 || alg == algPS256
	case ed25519.PublicKey:
		return alg == algEdDSA
	}
	return false
}

// verifySignature verifies a JWS signature with an asymmetric key.
func verifySignature(alg string, pub crypto.PublicKey, input, sig []byte) error {
	if !algMatchesKey(alg, pub) {
		return errors.New("algorithm does not match key")
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		var h hash.Hash
		size := 32
		if alg == algES384 {
			h, size = sha512.New384(), 48
		} else {
			h = sha256.New()
		}
		if len(sig) != 2*size {
			return errors.New("bad ECDSA signature length")
		}
		h.Write(input)
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(k, h.Sum(nil), r, s) {
			return errors.New("ECDSA verification failed")
		}
		return nil
	case *rsa.PublicKey:
		d := sha256.Sum256(input)
		if alg == algPS256 {
			return rsa.VerifyPSS(k, crypto.SHA256, d[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, d[:], sig)
	case ed25519.PublicKey:
		if !ed25519.Verify(k, input, sig) {
			return errors.New("Ed25519 verification failed")
		}
		return nil
	}
	return errors.New("unsupported key")
}

// verifyEAB checks an external account binding JWS (RFC 8555 §7.3.4) and
// returns the EAB key ID and the bound host account reference.
func verifyEAB(raw json.RawMessage, outerURL string, accountKey crypto.PublicKey, lookup func(kid string) ([]byte, string, error)) (string, string, *Problem) {
	j, prob := parseJWS(raw)
	if prob != nil {
		prob.Detail = "externalAccountBinding: " + prob.Detail
		return "", "", prob
	}
	h := j.header
	var newHash func() hash.Hash
	switch h.Alg {
	case "HS256":
		newHash = sha256.New
	case "HS384":
		newHash = sha512.New384
	case "HS512":
		newHash = sha512.New
	default:
		p := newProblem(ProbBadSignatureAlgorithm, http.StatusBadRequest, "externalAccountBinding algorithm %q is not supported", h.Alg)
		p.Algorithms = []string{"HS256", "HS384", "HS512"}
		return "", "", p
	}
	if h.KID == "" {
		return "", "", malformed("externalAccountBinding has no kid")
	}
	if h.Nonce != "" {
		return "", "", malformed("externalAccountBinding must not contain a nonce")
	}
	if len(h.JWK) > 0 {
		return "", "", malformed("externalAccountBinding must not contain a jwk header")
	}
	if h.URL != outerURL {
		return "", "", unauthorized("externalAccountBinding url does not match request url")
	}
	bound, prob := parseJWK(j.payload)
	if prob != nil {
		return "", "", malformed("externalAccountBinding payload is not a valid JWK")
	}
	if !publicKeysEqual(bound, accountKey) {
		return "", "", unauthorized("externalAccountBinding payload does not match the account key")
	}
	key, ref, err := lookup(h.KID)
	if err != nil {
		return "", "", unauthorized("externalAccountBinding key is unknown or not usable")
	}
	if len(key) < minEABKeyLen {
		return "", "", serverInternal("externalAccountBinding key is too short")
	}
	mac := hmac.New(newHash, key)
	mac.Write(j.signingInput)
	if !hmac.Equal(mac.Sum(nil), j.signature) {
		return "", "", unauthorized("externalAccountBinding signature is invalid")
	}
	return h.KID, ref, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface {
		Equal(crypto.PublicKey) bool
	}
	ea, ok := a.(equaler)
	return ok && b != nil && ea.Equal(b)
}

// trimURL normalizes a configured base URL.
func trimURL(u string) string { return strings.TrimRight(u, "/") }
