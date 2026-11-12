package jose

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// MaxTokenSize bounds the compact serializations ParseCompact accepts.
const MaxTokenSize = 64 << 10

var b64 = base64.RawURLEncoding.Strict()

// ErrMalformed is returned for a token that is not a well-formed compact JWS.
var ErrMalformed = errors.New("jose: malformed JWS")

// ErrSignature is returned when a signature does not verify.
var ErrSignature = errors.New("jose: signature verification failed")

// Signer produces JWS signatures. It is shaped so that a KMS-held key can
// implement it: the KMS never sees the JWS signing input, only its digest.
//
// Sign receives the digest of the JWS signing input
// (ASCII(BASE64URL(header) || '.' || BASE64URL(payload))) computed with
// HashFor(Alg()): SHA-256 for ES256/RS256/PS256 and SHA-384 for ES384. That is
// exactly what a KMS Sign call with MessageType=DIGEST expects
// (ECDSA_SHA_256, ECDSA_SHA_384, RSASSA_PKCS1_V1_5_SHA_256,
// RSASSA_PSS_SHA_256 respectively).
//
// The returned signature is:
//   - ES256/ES384: either ASN.1 DER (what crypto.Signer and AWS-style KMS
//     return) or the fixed-width JWS form R||S; both are accepted and
//     normalised to R||S.
//   - RS256: an RSASSA-PKCS1-v1_5 signature.
//   - PS256: an RSASSA-PSS signature with MGF1-SHA-256 and a 32-byte salt
//     (salt length equal to the hash length, as RFC 7518 requires).
//
// Every signature is verified against Public() before a token is returned,
// so a misconfigured key ID or key mismatch fails closed.
type Signer interface {
	Alg() string
	KeyID() string
	Public() crypto.PublicKey
	Sign(ctx context.Context, digest []byte) ([]byte, error)
}

// LocalSigner adapts an in-process crypto.Signer (*ecdsa.PrivateKey,
// *rsa.PrivateKey) to Signer. It is used in tests and for deployments that do
// not keep issuer keys in KMS.
type LocalSigner struct {
	key crypto.Signer
	alg string
	kid string
}

// NewLocalSigner wraps key for alg. If kid is empty, the RFC 7638 SHA-256
// thumbprint of the public key is used.
func NewLocalSigner(key crypto.Signer, alg, kid string) (*LocalSigner, error) {
	if err := CheckKey(alg, key.Public()); err != nil {
		return nil, err
	}
	if kid == "" {
		t, err := Thumbprint(key.Public())
		if err != nil {
			return nil, err
		}
		kid = t
	}
	return &LocalSigner{key: key, alg: alg, kid: kid}, nil
}

func (s *LocalSigner) Alg() string              { return s.alg }
func (s *LocalSigner) KeyID() string            { return s.kid }
func (s *LocalSigner) Public() crypto.PublicKey { return s.key.Public() }

// Sign signs digest (see Signer).
func (s *LocalSigner) Sign(_ context.Context, digest []byte) ([]byte, error) {
	h, err := HashFor(s.alg)
	if err != nil {
		return nil, err
	}
	if len(digest) != h.Size() {
		return nil, fmt.Errorf("jose: digest is %d bytes, want %d", len(digest), h.Size())
	}
	var opts crypto.SignerOpts = h
	if s.alg == PS256 {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
	}
	return s.key.Sign(rand.Reader, digest, opts)
}

// Header is the protected header of a JWS.
type Header struct {
	Alg string
	Kid string
	Typ string
	// Raw holds every header parameter, including the ones above.
	Raw map[string]any
}

// JWS is a parsed (not yet verified) compact JWS.
type JWS struct {
	Header       Header
	Payload      []byte
	SigningInput string // BASE64URL(header) "." BASE64URL(payload)
	Signature    []byte
}

type protectedHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	Typ string `json:"typ,omitempty"`
}

// Sign creates a compact JWS over payload with s. typ is optional ("JWT" for
// tokens).
func Sign(ctx context.Context, s Signer, payload []byte, typ string) (string, error) {
	alg := s.Alg()
	if err := CheckKey(alg, s.Public()); err != nil {
		return "", err
	}
	hdr, err := json.Marshal(protectedHeader{Alg: alg, Kid: s.KeyID(), Typ: typ})
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(hdr) + "." + b64.EncodeToString(payload)
	digest, err := Digest(alg, []byte(input))
	if err != nil {
		return "", err
	}
	sig, err := s.Sign(ctx, digest)
	if err != nil {
		return "", fmt.Errorf("jose: signer %q: %w", s.KeyID(), err)
	}
	if alg == ES256 || alg == ES384 {
		if sig, err = normalizeECDSA(sig, ecSize(alg)); err != nil {
			return "", err
		}
	}
	// Fail closed if the signer (for example a KMS key) does not match the
	// public key that will be published.
	if err := verifyDigest(alg, s.Public(), digest, sig); err != nil {
		return "", fmt.Errorf("jose: signer %q produced a signature that does not verify against its public key: %w", s.KeyID(), err)
	}
	return input + "." + b64.EncodeToString(sig), nil
}

// SignJWT marshals claims to JSON and signs it with typ "JWT".
func SignJWT(ctx context.Context, s Signer, claims any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return Sign(ctx, s, payload, "JWT")
}

// ParseCompact parses a compact JWS without verifying it. It rejects tokens
// whose alg is not supported, or not in allowedAlgs when that is non-empty,
// and tokens carrying a "crit" header (no extensions are understood).
func ParseCompact(token string, allowedAlgs ...string) (*JWS, error) {
	if len(token) > MaxTokenSize {
		return nil, fmt.Errorf("%w: token too large", ErrMalformed)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: want 3 segments, got %d", ErrMalformed, len(parts))
	}
	hdrBytes, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header encoding", ErrMalformed)
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload encoding", ErrMalformed)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature encoding", ErrMalformed)
	}
	raw := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(hdrBytes))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%w: header JSON", ErrMalformed)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing header data", ErrMalformed)
	}
	alg, _ := raw["alg"].(string)
	if !IsSupported(alg) {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlg, alg)
	}
	if len(allowedAlgs) > 0 && !contains(allowedAlgs, alg) {
		return nil, fmt.Errorf("%w: %q not allowed here", ErrUnsupportedAlg, alg)
	}
	if _, ok := raw["crit"]; ok {
		return nil, fmt.Errorf("%w: crit header not supported", ErrMalformed)
	}
	kid, _ := raw["kid"].(string)
	typ, _ := raw["typ"].(string)
	if len(sig) == 0 {
		return nil, fmt.Errorf("%w: empty signature", ErrMalformed)
	}
	return &JWS{
		Header:       Header{Alg: alg, Kid: kid, Typ: typ, Raw: raw},
		Payload:      payload,
		SigningInput: parts[0] + "." + parts[1],
		Signature:    sig,
	}, nil
}

// Verify checks the signature with pub.
func (j *JWS) Verify(pub crypto.PublicKey) error {
	digest, err := Digest(j.Header.Alg, []byte(j.SigningInput))
	if err != nil {
		return err
	}
	return verifyDigest(j.Header.Alg, pub, digest, j.Signature)
}

// KeySource resolves the verification key for a token header.
type KeySource interface {
	Key(ctx context.Context, kid, alg string) (crypto.PublicKey, error)
}

// Verify parses token, resolves its key from keys and verifies the
// signature. It returns the parsed JWS; claims are not validated.
func Verify(ctx context.Context, token string, keys KeySource, allowedAlgs ...string) (*JWS, error) {
	j, err := ParseCompact(token, allowedAlgs...)
	if err != nil {
		return nil, err
	}
	pub, err := keys.Key(ctx, j.Header.Kid, j.Header.Alg)
	if err != nil {
		return nil, err
	}
	if err := j.Verify(pub); err != nil {
		return nil, err
	}
	return j, nil
}

func verifyDigest(alg string, pub crypto.PublicKey, digest, sig []byte) error {
	if err := CheckKey(alg, pub); err != nil {
		return err
	}
	h, _ := HashFor(alg)
	switch alg {
	case ES256, ES384:
		n := ecSize(alg)
		if len(sig) != 2*n {
			return fmt.Errorf("%w: bad ECDSA signature length", ErrSignature)
		}
		r := new(big.Int).SetBytes(sig[:n])
		s := new(big.Int).SetBytes(sig[n:])
		if !ecdsa.Verify(pub.(*ecdsa.PublicKey), digest, r, s) {
			return ErrSignature
		}
		return nil
	case RS256:
		if err := rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), h, digest, sig); err != nil {
			return ErrSignature
		}
		return nil
	case PS256:
		if err := rsa.VerifyPSS(pub.(*rsa.PublicKey), h, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}); err != nil {
			return ErrSignature
		}
		return nil
	}
	return ErrUnsupportedAlg
}

// normalizeECDSA turns a DER or raw R||S ECDSA signature into fixed-width
// R||S of 2*n bytes.
func normalizeECDSA(sig []byte, n int) ([]byte, error) {
	var parsed struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(sig, &parsed)
	if err == nil && len(rest) == 0 && parsed.R != nil && parsed.S != nil {
		if parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 || parsed.R.BitLen() > 8*n || parsed.S.BitLen() > 8*n {
			return nil, fmt.Errorf("%w: ECDSA signature out of range", ErrSignature)
		}
		out := make([]byte, 2*n)
		parsed.R.FillBytes(out[:n])
		parsed.S.FillBytes(out[n:])
		return out, nil
	}
	if len(sig) == 2*n {
		return sig, nil
	}
	return nil, fmt.Errorf("%w: unrecognised ECDSA signature encoding", ErrSignature)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
