package jose

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
)

// Claim validation errors. Validate wraps one of these.
var (
	ErrClaimMissing   = errors.New("jose: required claim missing")
	ErrClaimInvalid   = errors.New("jose: claim has invalid type or value")
	ErrIssuer         = errors.New("jose: issuer mismatch")
	ErrAudience       = errors.New("jose: audience mismatch")
	ErrExpired        = errors.New("jose: token expired")
	ErrNotYetValid    = errors.New("jose: token not yet valid")
	ErrIssuedInFuture = errors.New("jose: token issued in the future")
)

// Claims is a decoded JWT claims set. Numbers are json.Number.
type Claims map[string]any

// ParseClaims decodes a JWT payload, preserving numbers as json.Number.
func ParseClaims(payload []byte) (Claims, error) {
	c := Claims{}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%w: claims JSON: %v", ErrClaimInvalid, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after claims", ErrClaimInvalid)
	}
	return c, nil
}

// String returns a string claim ("" if absent). A present non-string claim
// yields an error.
func (c Claims) String(name string) (string, error) {
	v, ok := c[name]
	if !ok || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w: %s is not a string", ErrClaimInvalid, name)
	}
	return s, nil
}

// Audience returns the aud claim, which may be a string or array of strings.
func (c Claims) Audience() ([]string, error) {
	switch v := c["aud"].(type) {
	case nil:
		return nil, nil
	case string:
		return []string{v}, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, a := range v {
			s, ok := a.(string)
			if !ok {
				return nil, fmt.Errorf("%w: aud element is not a string", ErrClaimInvalid)
			}
			out = append(out, s)
		}
		return out, nil
	case []string:
		return v, nil
	}
	return nil, fmt.Errorf("%w: aud is neither string nor array", ErrClaimInvalid)
}

// Time returns a NumericDate claim. ok is false when absent.
func (c Claims) Time(name string) (t time.Time, ok bool, err error) {
	v, present := c[name]
	if !present || v == nil {
		return time.Time{}, false, nil
	}
	var f float64
	switch n := v.(type) {
	case json.Number:
		f, err = n.Float64()
		if err != nil {
			return time.Time{}, true, fmt.Errorf("%w: %s", ErrClaimInvalid, name)
		}
	case float64:
		f = n
	case int64:
		f = float64(n)
	case int:
		f = float64(n)
	default:
		return time.Time{}, true, fmt.Errorf("%w: %s is not a number", ErrClaimInvalid, name)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1<<40 {
		return time.Time{}, true, fmt.Errorf("%w: %s out of range", ErrClaimInvalid, name)
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)), true, nil
}

// Validator checks the registered claims of a JWT.
type Validator struct {
	// Issuer, if set, must equal iss exactly.
	Issuer string
	// Audience, if set, must be one of the aud values (string or array).
	Audience string
	// Leeway tolerates clock skew for exp, nbf and iat.
	Leeway time.Duration
	// Now defaults to time.Now.
	Now func() time.Time
	// Required lists additional claims that must be present and non-null.
	Required []string
	// RequireIssuedAt makes iat mandatory. exp is always mandatory.
	RequireIssuedAt bool
	// MaxAge, if set, rejects tokens whose iat is older than MaxAge.
	MaxAge time.Duration
}

// Validate checks c. exp is always required.
func (v Validator) Validate(c Claims) error {
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	for _, name := range v.Required {
		if val, ok := c[name]; !ok || val == nil {
			return fmt.Errorf("%w: %s", ErrClaimMissing, name)
		}
	}
	if v.Issuer != "" {
		iss, err := c.String("iss")
		if err != nil {
			return err
		}
		if iss != v.Issuer {
			return fmt.Errorf("%w: got %q", ErrIssuer, iss)
		}
	}
	if v.Audience != "" {
		aud, err := c.Audience()
		if err != nil {
			return err
		}
		if !contains(aud, v.Audience) {
			return fmt.Errorf("%w: %q not in %q", ErrAudience, v.Audience, aud)
		}
	}
	exp, ok, err := c.Time("exp")
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: exp", ErrClaimMissing)
	}
	if !now.Before(exp.Add(v.Leeway)) {
		return fmt.Errorf("%w at %s", ErrExpired, exp.UTC().Format(time.RFC3339))
	}
	nbf, ok, err := c.Time("nbf")
	if err != nil {
		return err
	}
	if ok && now.Add(v.Leeway).Before(nbf) {
		return fmt.Errorf("%w until %s", ErrNotYetValid, nbf.UTC().Format(time.RFC3339))
	}
	iat, ok, err := c.Time("iat")
	if err != nil {
		return err
	}
	if !ok && (v.RequireIssuedAt || v.MaxAge > 0) {
		return fmt.Errorf("%w: iat", ErrClaimMissing)
	}
	if ok {
		if now.Add(v.Leeway).Before(iat) {
			return ErrIssuedInFuture
		}
		if v.MaxAge > 0 && now.Sub(iat) > v.MaxAge+v.Leeway {
			return fmt.Errorf("%w: issued too long ago", ErrExpired)
		}
	}
	return nil
}
