// Package sigv4 parses and verifies AWS Signature Version 4 request
// signatures (full signature recomputation). It has no server dependencies.
package sigv4

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// MaxClockSkew bounds how far X-Amz-Date may drift from server time. AWS
// uses the same 15-minute window; it is what stops a captured request from
// being replayed indefinitely.
const MaxClockSkew = 15 * time.Minute

// CheckAmzDate validates X-Amz-Date: it must parse, agree with the credential
// scope's date, and fall within MaxClockSkew of now.
func CheckAmzDate(amzDate, scopeDate string, now time.Time) error {
	amzDate = strings.TrimSpace(amzDate)
	if amzDate == "" {
		return errors.New("missing X-Amz-Date header")
	}
	t, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		return errors.New("malformed X-Amz-Date header")
	}
	if scopeDate != "" && !strings.HasPrefix(amzDate, scopeDate) {
		return errors.New("X-Amz-Date does not match credential scope date")
	}
	if d := now.Sub(t); d > MaxClockSkew || d < -MaxClockSkew {
		return fmt.Errorf("request time %s is outside the allowed clock skew", amzDate)
	}
	return nil
}

type Components struct {
	AccessKey     string
	Scope         string
	SignedHeaders []string
	Signature     string
	Region        string
	Service       string
	Date          string // yyyymmdd
}

func ParseAuthorizationHeader(auth string) (Components, error) {
	var c Components
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		return c, errors.New("unsupported authorization algorithm")
	}
	rest := strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 ")
	for _, segment := range strings.Split(rest, ",") {
		segment = strings.TrimSpace(segment)
		switch {
		case strings.HasPrefix(segment, "Credential="):
			cred := strings.TrimPrefix(segment, "Credential=")
			pieces := strings.Split(cred, "/")
			if len(pieces) != 5 {
				return c, errors.New("malformed Credential scope")
			}
			c.AccessKey = pieces[0]
			c.Date = pieces[1]
			c.Region = pieces[2]
			c.Service = pieces[3]
			c.Scope = strings.Join(pieces[1:], "/")
		case strings.HasPrefix(segment, "SignedHeaders="):
			c.SignedHeaders = strings.Split(strings.TrimPrefix(segment, "SignedHeaders="), ";")
		case strings.HasPrefix(segment, "Signature="):
			c.Signature = strings.TrimPrefix(segment, "Signature=")
		}
	}
	if c.AccessKey == "" || len(c.SignedHeaders) == 0 || c.Signature == "" {
		return c, errors.New("incomplete authorization header")
	}
	return c, nil
}

func HMACSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func DeriveSigningKey(secretKey, date, region, service string) []byte {
	kDate := HMACSHA256([]byte("AWS4"+secretKey), []byte(date))
	kRegion := HMACSHA256(kDate, []byte(region))
	kService := HMACSHA256(kRegion, []byte(service))
	return HMACSHA256(kService, []byte("aws4_request"))
}

// VerifySignature recomputes the SigV4 signature and compares it in
// constant time. bodyHash must be the lowercase hex SHA-256 of the request body.
func VerifySignature(r *http.Request, bodyHash, secretKey string) error {
	comp, err := ParseAuthorizationHeader(r.Header.Get("Authorization"))
	if err != nil {
		return err
	}
	amzDate := r.Header.Get("X-Amz-Date")
	if amzDate == "" {
		return errors.New("missing X-Amz-Date header")
	}

	// Canonical headers (only the signed headers, in the given order which the
	// client already sorted per spec).
	var canonicalHeaders strings.Builder
	for _, h := range comp.SignedHeaders {
		canonicalHeaders.WriteString(strings.ToLower(h))
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(CanonicalHeaderValue(r, h))
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(comp.SignedHeaders, ";")

	canonicalQuery := CanonicalQueryString(r.URL.RawQuery)
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	canonicalRequest := strings.Join([]string{
		r.Method,
		path,
		canonicalQuery,
		canonicalHeaders.String(),
		signedHeaders,
		bodyHash,
	}, "\n")

	hashedCanonical := sha256.Sum256([]byte(canonicalRequest))
	credentialScope := comp.Scope
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		hex.EncodeToString(hashedCanonical[:]),
	}, "\n")

	signingKey := DeriveSigningKey(secretKey, comp.Date, comp.Region, comp.Service)
	expected := hex.EncodeToString(HMACSHA256(signingKey, []byte(stringToSign)))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(comp.Signature)) != 1 {
		return errors.New("signature mismatch")
	}
	return nil
}

// CanonicalHeaderValue returns a signed header's canonical value: all values
// joined with commas, trimmed, sequential spaces collapsed. Go's server moves
// Host and Content-Length out of the header map, so they are read from the
// request itself.
func CanonicalHeaderValue(r *http.Request, name string) string {
	switch strings.ToLower(name) {
	case "host":
		return r.Host
	case "content-length":
		if v := r.Header.Get("Content-Length"); v != "" {
			return strings.TrimSpace(v)
		}
		if r.ContentLength >= 0 {
			return strconv.FormatInt(r.ContentLength, 10)
		}
		return ""
	}
	values := r.Header.Values(name)
	for i, v := range values {
		values[i] = strings.Join(strings.Fields(v), " ")
	}
	return strings.Join(values, ",")
}

// CanonicalQueryString builds the SigV4 canonical query string from a raw
// query: each name and value URI-encoded per RFC 3986 (unreserved characters
// kept, everything else %XX with uppercase hex, so a space is %20 and never
// "+"), then sorted by name and value. url.Values.Encode writes a space as
// "+", which breaks the signature of any query value containing a space.
func CanonicalQueryString(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	type pair struct{ k, v string }
	var pairs []pair
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		pairs = append(pairs, pair{URIEncode(queryUnescape(k)), URIEncode(queryUnescape(v))})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(p.k)
		b.WriteByte('=')
		b.WriteString(p.v)
	}
	return b.String()
}

// queryUnescape decodes %XX escapes. A literal "+" stays "+": AWS clients
// encode a plus as %2B and a space as %20, so "+" in a raw query is a plus.
func queryUnescape(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}

// URIEncode percent-encodes s per the SigV4 rules (RFC 3986 unreserved set).
func URIEncode(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&15])
	}
	return b.String()
}

// DrainAndHashBody reads (up to the limit), returns a fresh ReadCloser for
// downstream handlers, and the lowercase hex SHA-256 of the body.
func DrainAndHashBody(r *http.Request, limit int64) (string, error) {
	if r.Body == nil {
		sum := sha256.Sum256(nil)
		return hex.EncodeToString(sum[:]), nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit))
	if err != nil {
		return "", err
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}
