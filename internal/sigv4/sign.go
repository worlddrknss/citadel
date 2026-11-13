package sigv4

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"
)

// UnsignedPayload is the payload hash for requests whose body is not signed
// (S3 only).
const UnsignedPayload = "UNSIGNED-PAYLOAD"

// MinSecretKeyLen is the shortest secret access key SignRequest accepts:
// with the "AWS4" prefix it makes a 14-byte (112-bit) HMAC key, the minimum
// Go's FIPS 140-3 module allows.
const MinSecretKeyLen = 10

// SigningCredentials are the AWS credentials an outbound request is signed
// with. SessionToken is set for temporary (STS) credentials.
type SigningCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// HashPayload returns the lowercase hex SHA-256 of body, the payload hash
// SignRequest takes.
func HashPayload(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// SignRequest signs an outbound request with SigV4 (the client side of
// VerifySignature). It sets X-Amz-Date, X-Amz-Content-Sha256 and, for
// temporary credentials, X-Amz-Security-Token, then the Authorization
// header. payloadHash is HashPayload(body) (or UnsignedPayload for S3).
//
// The signed headers are host, content-type (when present) and every x-amz-*
// header. The canonical URI is the RFC 3986 encoding of the path; services
// other than s3 encode it a second time, as AWS requires. The request's
// RawPath is rewritten to the single-encoded form so that what goes on the
// wire matches what was signed.
func SignRequest(req *http.Request, payloadHash string, creds SigningCredentials, region, service string, now time.Time) error {
	if req == nil || req.URL == nil {
		return errors.New("sigv4: nil request")
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return errors.New("sigv4: missing signing credentials")
	}
	// The first HMAC key is "AWS4"+secret; FIPS 140-only mode panics on
	// HMAC keys under 112 bits. Real AWS secret keys are 40 characters.
	if len(creds.SecretAccessKey) < MinSecretKeyLen {
		return errors.New("sigv4: secret access key is too short")
	}
	if region == "" || service == "" {
		return errors.New("sigv4: region and service are required")
	}
	if payloadHash == "" {
		return errors.New("sigv4: payload hash is required")
	}
	if req.Header == nil {
		req.Header = http.Header{}
	}
	now = now.UTC()
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")

	req.Header.Del("Authorization")
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	} else {
		req.Header.Del("X-Amz-Security-Token")
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if host == "" {
		return errors.New("sigv4: request has no host")
	}

	// Signed headers: host, content-type and x-amz-*, lowercased and sorted.
	values := map[string]string{"host": host}
	for name := range req.Header {
		lower := strings.ToLower(name)
		if lower == "content-type" || strings.HasPrefix(lower, "x-amz-") {
			vs := req.Header.Values(name)
			for i, v := range vs {
				vs[i] = strings.Join(strings.Fields(v), " ")
			}
			values[lower] = strings.Join(vs, ",")
		}
	}
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	sort.Strings(names)
	var canonicalHeaders strings.Builder
	for _, n := range names {
		canonicalHeaders.WriteString(n)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(values[n])
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(names, ";")

	wirePath := encodePath(req.URL.EscapedPath())
	req.URL.RawPath = wirePath
	canonicalPath := wirePath
	if service != "s3" {
		segs := strings.Split(wirePath, "/")
		for i, s := range segs {
			segs[i] = URIEncode(s)
		}
		canonicalPath = strings.Join(segs, "/")
	}

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalPath,
		CanonicalQueryString(req.URL.RawQuery),
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")
	hashed := sha256.Sum256([]byte(canonicalRequest))
	scope := date + "/" + region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hex.EncodeToString(hashed[:]),
	}, "\n")
	key := DeriveSigningKey(creds.SecretAccessKey, date, region, service)
	sig := hex.EncodeToString(HMACSHA256(key, []byte(stringToSign)))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+creds.AccessKeyID+"/"+scope+
		", SignedHeaders="+signedHeaders+", Signature="+sig)
	return nil
}

// encodePath re-encodes each segment of an escaped path per RFC 3986
// (decoding it first, so an encoded slash stays inside its segment), keeping
// the separating slashes. An empty path is "/".
func encodePath(escaped string) string {
	if escaped == "" {
		return "/"
	}
	segs := strings.Split(escaped, "/")
	for i, s := range segs {
		segs[i] = URIEncode(queryUnescape(s))
	}
	return strings.Join(segs, "/")
}
