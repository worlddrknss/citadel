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
		value := r.Header.Get(h)
		if strings.EqualFold(h, "host") {
			value = r.Host
		}
		canonicalHeaders.WriteString(strings.ToLower(h))
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.TrimSpace(value))
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(comp.SignedHeaders, ";")

	canonicalQuery := r.URL.Query().Encode()
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
