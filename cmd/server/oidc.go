package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ecCurve maps a JWK "crv" name to its elliptic.Curve.
func ecCurve(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", crv)
	}
}

// Minimal OIDC web-identity verification used by STS AssumeRoleWithWebIdentity.
//
// The verifier is intentionally dependency-free (Go stdlib only, matching the
// rest of the project) and supports the signature algorithms used in practice
// by Kubernetes service-account tokens and common identity providers: RS256/384/512
// and ES256/384/512. Tokens are validated for signature, issuer, audience and
// expiry; the resolved claims (issuer, subject, audiences) are returned for the
// caller to match against a role trust policy.

// oidcClaims is the subset of standard JWT claims STS needs.
type oidcClaims struct {
	Issuer    string
	Subject   string
	Audiences []string
	ExpiresAt time.Time
}

// rawJWTClaims mirrors the JSON payload. "aud" may be a string or array, so it
// is decoded leniently.
type rawJWTClaims struct {
	Issuer    string          `json:"iss"`
	Subject   string          `json:"sub"`
	Audience  json.RawMessage `json:"aud"`
	ExpiresAt int64           `json:"exp"`
	NotBefore int64           `json:"nbf"`
}

// jwksCache memoizes fetched JWKS per issuer for a short TTL to avoid hammering
// the provider on every AssumeRoleWithWebIdentity call.
type jwksCache struct {
	mu      sync.Mutex
	entries map[string]jwksCacheEntry
}

type jwksCacheEntry struct {
	keys      map[string]crypto.PublicKey // kid -> public key
	fetchedAt time.Time
}

var globalJWKSCache = &jwksCache{entries: map[string]jwksCacheEntry{}}

const jwksCacheTTL = 5 * time.Minute

// jwk is a single JSON Web Key (RSA or EC).
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

type oidcDiscovery struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// verifyWebIdentityToken validates a JWT against the issuer's published JWKS and
// returns its claims. The HTTP client is used for OIDC discovery and key fetch.
func verifyWebIdentityToken(ctx context.Context, client *http.Client, token string) (oidcClaims, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return oidcClaims{}, errors.New("malformed JWT: expected 3 segments")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return oidcClaims{}, fmt.Errorf("decode JWT header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return oidcClaims{}, fmt.Errorf("parse JWT header: %w", err)
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return oidcClaims{}, fmt.Errorf("decode JWT payload: %w", err)
	}
	var raw rawJWTClaims
	if err := json.Unmarshal(payloadJSON, &raw); err != nil {
		return oidcClaims{}, fmt.Errorf("parse JWT payload: %w", err)
	}
	if strings.TrimSpace(raw.Issuer) == "" {
		return oidcClaims{}, errors.New("JWT missing iss claim")
	}
	if strings.TrimSpace(raw.Subject) == "" {
		return oidcClaims{}, errors.New("JWT missing sub claim")
	}

	now := time.Now().UTC()
	if raw.ExpiresAt == 0 {
		return oidcClaims{}, errors.New("JWT missing exp claim")
	}
	exp := time.Unix(raw.ExpiresAt, 0).UTC()
	if now.After(exp) {
		return oidcClaims{}, errors.New("JWT is expired")
	}
	if raw.NotBefore != 0 && now.Add(60*time.Second).Before(time.Unix(raw.NotBefore, 0).UTC()) {
		return oidcClaims{}, errors.New("JWT not yet valid")
	}

	// Resolve the signing key for this issuer/kid and verify the signature.
	pub, err := globalJWKSCache.keyFor(ctx, client, raw.Issuer, header.Kid)
	if err != nil {
		return oidcClaims{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return oidcClaims{}, fmt.Errorf("decode JWT signature: %w", err)
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	if err := verifyJWTSignature(header.Alg, pub, signingInput, signature); err != nil {
		return oidcClaims{}, err
	}

	return oidcClaims{
		Issuer:    normalizeIssuerURL(raw.Issuer),
		Subject:   raw.Subject,
		Audiences: decodeAudience(raw.Audience),
		ExpiresAt: exp,
	}, nil
}

// decodeAudience handles both string and []string forms of the aud claim.
func decodeAudience(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many
	}
	return nil
}

// verifyJWTSignature checks the JWT signature using the resolved public key.
func verifyJWTSignature(alg string, pub crypto.PublicKey, signingInput, signature []byte) error {
	var hashed []byte
	var hash crypto.Hash
	switch alg {
	case "RS256", "ES256":
		sum := sha256.Sum256(signingInput)
		hashed, hash = sum[:], crypto.SHA256
	case "RS384", "ES384":
		sum := sha512.Sum384(signingInput)
		hashed, hash = sum[:], crypto.SHA384
	case "RS512", "ES512":
		sum := sha512.Sum512(signingInput)
		hashed, hash = sum[:], crypto.SHA512
	default:
		return fmt.Errorf("unsupported JWT alg: %s", alg)
	}

	switch strings.HasPrefix(alg, "RS") {
	case true:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("RSA alg but key is not RSA")
		}
		if err := rsa.VerifyPKCS1v15(rsaPub, hash, hashed, signature); err != nil {
			return errors.New("JWT signature verification failed")
		}
		return nil
	default: // ES*
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("EC alg but key is not EC")
		}
		// JWS ECDSA signatures are the raw r||s concatenation.
		half := len(signature) / 2
		if half == 0 {
			return errors.New("invalid ECDSA signature length")
		}
		r := new(big.Int).SetBytes(signature[:half])
		sInt := new(big.Int).SetBytes(signature[half:])
		if !ecdsa.Verify(ecPub, hashed, r, sInt) {
			return errors.New("JWT signature verification failed")
		}
		return nil
	}
}

// keyFor returns the public key for the given issuer and kid, fetching and
// caching the issuer's JWKS as needed.
func (c *jwksCache) keyFor(ctx context.Context, client *http.Client, issuer, kid string) (crypto.PublicKey, error) {
	issuer = normalizeIssuerURL(issuer)
	c.mu.Lock()
	entry, ok := c.entries[issuer]
	fresh := ok && time.Since(entry.fetchedAt) < jwksCacheTTL
	c.mu.Unlock()

	if fresh {
		if k := selectKey(entry.keys, kid); k != nil {
			return k, nil
		}
	}

	keys, err := fetchJWKS(ctx, client, issuer)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.entries[issuer] = jwksCacheEntry{keys: keys, fetchedAt: time.Now()}
	c.mu.Unlock()

	if k := selectKey(keys, kid); k != nil {
		return k, nil
	}
	return nil, errors.New("no matching JWKS key for token kid")
}

// selectKey returns the key for kid, or the sole key when kid is empty/unique.
func selectKey(keys map[string]crypto.PublicKey, kid string) crypto.PublicKey {
	if kid != "" {
		if k, ok := keys[kid]; ok {
			return k
		}
		return nil
	}
	if len(keys) == 1 {
		for _, k := range keys {
			return k
		}
	}
	return nil
}

// fetchJWKS performs OIDC discovery and downloads/parses the issuer's JWKS.
func fetchJWKS(ctx context.Context, client *http.Client, issuer string) (map[string]crypto.PublicKey, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	disco, err := httpGetJSON[oidcDiscovery](ctx, client, strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	if strings.TrimSpace(disco.JWKSURI) == "" {
		return nil, errors.New("oidc discovery missing jwks_uri")
	}
	doc, err := httpGetJSON[jwksDocument](ctx, client, disco.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	out := make(map[string]crypto.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		pub, err := k.publicKey()
		if err != nil {
			continue // skip keys we cannot parse rather than failing the set
		}
		out[k.Kid] = pub
	}
	if len(out) == 0 {
		return nil, errors.New("jwks contained no usable keys")
	}
	return out, nil
}

// publicKey converts a JWK into a crypto.PublicKey (RSA or EC).
func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		if e == 0 {
			return nil, errors.New("invalid RSA exponent")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
	case "EC":
		curve, err := ecCurve(k.Crv)
		if err != nil {
			return nil, err
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported JWK kty: %s", k.Kty)
	}
}

// httpGetJSON fetches a URL and decodes the JSON body into T.
func httpGetJSON[T any](ctx context.Context, client *http.Client, url string) (T, error) {
	var zero T
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return zero, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return zero, err
	}
	return out, nil
}
