package jose

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// ErrKeyNotFound is returned when no key in a set matches a token header.
var ErrKeyNotFound = errors.New("jose: no matching key")

// JWK is a public JSON Web Key (RSA or EC P-256/P-384). Private key material
// is never marshalled and is rejected on parse.
type JWK struct {
	Key   crypto.PublicKey // *rsa.PublicKey or *ecdsa.PublicKey
	KeyID string
	Alg   string
	Use   string
}

type jwkJSON struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	// Private members; their presence is an error.
	D  string `json:"d,omitempty"`
	P  string `json:"p,omitempty"`
	Q  string `json:"q,omitempty"`
	DP string `json:"dp,omitempty"`
	DQ string `json:"dq,omitempty"`
	QI string `json:"qi,omitempty"`
	K  string `json:"k,omitempty"`
}

// NewJWK builds a JWK for a Signer's public key.
func NewJWK(s Signer) JWK {
	return JWK{Key: s.Public(), KeyID: s.KeyID(), Alg: s.Alg(), Use: "sig"}
}

// MarshalJSON implements json.Marshaler.
func (k JWK) MarshalJSON() ([]byte, error) {
	j, err := publicMembers(k.Key)
	if err != nil {
		return nil, err
	}
	j.Kid, j.Alg, j.Use = k.KeyID, k.Alg, k.Use
	return json.Marshal(j)
}

// UnmarshalJSON implements json.Unmarshaler.
func (k *JWK) UnmarshalJSON(data []byte) error {
	var j jwkJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	if j.D != "" || j.P != "" || j.Q != "" || j.DP != "" || j.DQ != "" || j.QI != "" || j.K != "" {
		return errors.New("jose: JWK contains private or symmetric key material")
	}
	var pub crypto.PublicKey
	switch j.Kty {
	case "EC":
		var curve elliptic.Curve
		var size int
		switch j.Crv {
		case "P-256":
			curve, size = elliptic.P256(), 32
		case "P-384":
			curve, size = elliptic.P384(), 48
		default:
			return fmt.Errorf("jose: unsupported EC curve %q", j.Crv)
		}
		x, err := b64.DecodeString(j.X)
		if err != nil || len(x) != size {
			return errors.New("jose: bad EC x coordinate")
		}
		y, err := b64.DecodeString(j.Y)
		if err != nil || len(y) != size {
			return errors.New("jose: bad EC y coordinate")
		}
		point := append(append([]byte{4}, x...), y...)
		ec, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return fmt.Errorf("jose: bad EC point: %w", err)
		}
		pub = ec
	case "RSA":
		n, err := b64.DecodeString(j.N)
		if err != nil || len(n) == 0 || n[0] == 0 {
			return errors.New("jose: bad RSA modulus")
		}
		e, err := b64.DecodeString(j.E)
		if err != nil || len(e) == 0 || len(e) > 4 || e[0] == 0 {
			return errors.New("jose: bad RSA exponent")
		}
		eInt := new(big.Int).SetBytes(e)
		if !eInt.IsInt64() || eInt.Int64() < 3 || eInt.Int64() > 1<<31-1 || eInt.Bit(0) == 0 {
			return errors.New("jose: bad RSA exponent")
		}
		rk := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(eInt.Int64())}
		if err := checkRSASize(rk); err != nil {
			return err
		}
		pub = rk
	default:
		return fmt.Errorf("jose: unsupported key type %q", j.Kty)
	}
	if j.Alg != "" {
		if !IsSupported(j.Alg) {
			return fmt.Errorf("%w: JWK alg %q", ErrUnsupportedAlg, j.Alg)
		}
		if err := CheckKey(j.Alg, pub); err != nil {
			return err
		}
	}
	*k = JWK{Key: pub, KeyID: j.Kid, Alg: j.Alg, Use: j.Use}
	return nil
}

func publicMembers(pub crypto.PublicKey) (jwkJSON, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		var crv string
		var size int
		switch k.Curve {
		case elliptic.P256():
			crv, size = "P-256", 32
		case elliptic.P384():
			crv, size = "P-384", 48
		default:
			return jwkJSON{}, fmt.Errorf("%w: unsupported curve", ErrKeyMismatch)
		}
		b, err := k.Bytes()
		if err != nil || len(b) != 1+2*size {
			return jwkJSON{}, fmt.Errorf("%w: invalid EC key", ErrKeyMismatch)
		}
		return jwkJSON{Kty: "EC", Crv: crv, X: b64.EncodeToString(b[1 : 1+size]), Y: b64.EncodeToString(b[1+size:])}, nil
	case *rsa.PublicKey:
		if err := checkRSASize(k); err != nil {
			return jwkJSON{}, err
		}
		e := big.NewInt(int64(k.E)).Bytes()
		return jwkJSON{Kty: "RSA", N: b64.EncodeToString(k.N.Bytes()), E: b64.EncodeToString(e)}, nil
	}
	return jwkJSON{}, fmt.Errorf("%w: unsupported key type %T", ErrKeyMismatch, pub)
}

// Thumbprint returns the base64url RFC 7638 SHA-256 thumbprint of pub.
func Thumbprint(pub crypto.PublicKey) (string, error) {
	j, err := publicMembers(pub)
	if err != nil {
		return "", err
	}
	// RFC 7638: required members only, lexicographic order, no whitespace.
	var canon string
	switch j.Kty {
	case "EC":
		canon = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, j.Crv, j.X, j.Y)
	case "RSA":
		canon = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, j.E, j.N)
	}
	sum := sha256.Sum256([]byte(canon))
	return b64.EncodeToString(sum[:]), nil
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint of the key.
func (k JWK) Thumbprint() (string, error) { return Thumbprint(k.Key) }

// JWKSet is a JSON Web Key Set.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// ParseJWKSet parses a JWKS document. Keys this package cannot use
// (unsupported kty/crv/alg, RSA keys under 2048 bits, encryption keys, keys
// carrying private material) are skipped rather than failing the whole set,
// because providers routinely publish such keys next to usable ones.
func ParseJWKSet(data []byte) (*JWKSet, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("jose: parse JWKS: %w", err)
	}
	if doc.Keys == nil {
		return nil, errors.New("jose: JWKS has no keys member")
	}
	set := &JWKSet{}
	for _, raw := range doc.Keys {
		var k JWK
		if err := json.Unmarshal(raw, &k); err != nil {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		set.Keys = append(set.Keys, k)
	}
	return set, nil
}

// Lookup finds the key for a token with the given kid and alg. When kid is
// empty, it succeeds only if exactly one key is usable with alg.
func (s *JWKSet) Lookup(kid, alg string) (*JWK, error) {
	if !IsSupported(alg) {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlg, alg)
	}
	var found *JWK
	n := 0
	for i := range s.Keys {
		k := &s.Keys[i]
		if kid != "" && k.KeyID != kid {
			continue
		}
		if k.Alg != "" && k.Alg != alg {
			continue
		}
		if CheckKey(alg, k.Key) != nil {
			continue
		}
		found = k
		n++
	}
	switch {
	case n == 0:
		return nil, fmt.Errorf("%w: kid %q alg %s", ErrKeyNotFound, kid, alg)
	case n > 1:
		return nil, fmt.Errorf("%w: kid %q alg %s is ambiguous", ErrKeyNotFound, kid, alg)
	}
	return found, nil
}

// Key implements KeySource.
func (s *JWKSet) Key(_ context.Context, kid, alg string) (crypto.PublicKey, error) {
	k, err := s.Lookup(kid, alg)
	if err != nil {
		return nil, err
	}
	return k.Key, nil
}
