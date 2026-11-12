// Package jose implements the subset of JOSE (RFC 7515 JWS, RFC 7517 JWK,
// RFC 7519 JWT, RFC 7638 thumbprints) that Citadel needs for OIDC sign-in and
// for its workload identity issuer.
//
// The package is deliberately conservative so that it runs unchanged under
// GOFIPS140=certified with GODEBUG=fips140=only:
//
//   - Only ES256, ES384, RS256 and PS256 are accepted. "none", every HMAC
//     algorithm (HS*) and EdDSA are always rejected, whatever the caller asks
//     for, which also rules out RSA-public-key-as-HMAC-secret confusion.
//   - RSA keys must be between 2048 and 8192 bits; EC keys must be on P-256
//     (ES256) or P-384 (ES384).
//   - Only SHA-256 and SHA-384 are used, and only crypto/rand.
//
// Only the standard library is used.
package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
)

// Supported JWS algorithms (RFC 7518 section 3.1).
const (
	ES256 = "ES256" // ECDSA P-256 with SHA-256
	ES384 = "ES384" // ECDSA P-384 with SHA-384
	RS256 = "RS256" // RSASSA-PKCS1-v1_5 with SHA-256
	PS256 = "PS256" // RSASSA-PSS with SHA-256, MGF1-SHA-256, salt length 32
)

// SupportedAlgorithms lists every algorithm this package will sign or verify.
var SupportedAlgorithms = []string{ES256, ES384, RS256, PS256}

const (
	minRSABits = 2048
	maxRSABits = 8192
)

var (
	// ErrUnsupportedAlg is returned for any algorithm outside
	// SupportedAlgorithms (including none, HS*, EdDSA).
	ErrUnsupportedAlg = errors.New("jose: unsupported or disallowed algorithm")
	// ErrKeyMismatch is returned when a key cannot be used with an algorithm.
	ErrKeyMismatch = errors.New("jose: key is not usable with algorithm")
)

// IsSupported reports whether alg is one of SupportedAlgorithms.
func IsSupported(alg string) bool {
	switch alg {
	case ES256, ES384, RS256, PS256:
		return true
	}
	return false
}

// HashFor returns the hash function an algorithm signs with. A Signer's Sign
// method receives a digest computed with this hash.
func HashFor(alg string) (crypto.Hash, error) {
	switch alg {
	case ES256, RS256, PS256:
		return crypto.SHA256, nil
	case ES384:
		return crypto.SHA384, nil
	}
	return 0, fmt.Errorf("%w: %q", ErrUnsupportedAlg, alg)
}

// Digest hashes data with the hash used by alg.
func Digest(alg string, data []byte) ([]byte, error) {
	h, err := HashFor(alg)
	if err != nil {
		return nil, err
	}
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256(data)
		return d[:], nil
	case crypto.SHA384:
		d := sha512.Sum384(data)
		return d[:], nil
	}
	return nil, ErrUnsupportedAlg
}

// CheckKey reports whether pub is an acceptable public key for alg.
func CheckKey(alg string, pub crypto.PublicKey) error {
	switch alg {
	case ES256, ES384:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: %s needs an ECDSA key, got %T", ErrKeyMismatch, alg, pub)
		}
		want := elliptic.P256()
		if alg == ES384 {
			want = elliptic.P384()
		}
		if k.Curve != want {
			return fmt.Errorf("%w: %s needs curve %s", ErrKeyMismatch, alg, want.Params().Name)
		}
		return nil
	case RS256, PS256:
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: %s needs an RSA key, got %T", ErrKeyMismatch, alg, pub)
		}
		return checkRSASize(k)
	}
	return fmt.Errorf("%w: %q", ErrUnsupportedAlg, alg)
}

func checkRSASize(k *rsa.PublicKey) error {
	if k.N == nil {
		return fmt.Errorf("%w: empty RSA modulus", ErrKeyMismatch)
	}
	if b := k.N.BitLen(); b < minRSABits || b > maxRSABits {
		return fmt.Errorf("%w: RSA modulus is %d bits (want %d..%d)", ErrKeyMismatch, b, minRSABits, maxRSABits)
	}
	return nil
}

// ecSize returns the coordinate size in bytes for an EC algorithm.
func ecSize(alg string) int {
	if alg == ES384 {
		return 48
	}
	return 32
}
