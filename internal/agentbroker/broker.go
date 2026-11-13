// Package agentbroker performs HTTP requests on behalf of AI agents with a
// credential injected, so the agent never holds the secret.
//
// It is pure request/response logic: validating the agent's request against
// the credential's usage profile (scheme, host, port, method, path),
// stripping agent headers that could collide with the credential, injecting
// it (http_header, http_basic, http_query), following same-host redirects,
// enforcing size limits, filtering response headers and redacting the
// secret from the response. Authentication, grants, the SSRF-guarded HTTP
// client, audit and metrics belong to the caller (internal/server).
package agentbroker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// Credential kinds the broker can inject. Other kinds (login, raw) are only
// usable through reveal.
const (
	KindHTTPHeader = "http_header"
	KindHTTPBasic  = "http_basic"
	KindHTTPQuery  = "http_query"
)

// Body encodings.
const (
	EncodingText   = "text"
	EncodingBase64 = "base64"
)

// Default limits (docs/design/agent-credentials.md).
const (
	DefaultMaxRequestBody  = 1 << 20
	DefaultMaxResponseBody = 5 << 20
	DefaultMaxRedirects    = 3
	DefaultTimeout         = 30 * time.Second

	maxHeaders        = 64
	maxHeaderBytes    = 32 << 10
	maxURLLength      = 8192
	defaultHeaderName = "Authorization"
)

// Methods the broker sends at all. A profile's allowedMethods narrows them.
var brokerMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodPatch: true, http.MethodDelete: true, http.MethodOptions: true,
}

// Profile is how a credential may be used: the usage profile minus the
// secret reference.
type Profile struct {
	Kind string
	// AllowedHosts are exact hosts ("api.github.com") or suffix wildcards
	// ("*.example.com", which does not match example.com itself), each
	// optionally with ":port". Without a port only the scheme's default
	// port is allowed.
	AllowedHosts []string
	// AllowedMethods narrows the methods; empty allows every method the
	// broker supports.
	AllowedMethods []string
	// AllowedPathPrefixes narrows paths; empty allows any path. A prefix
	// matches whole segments: "/repos" matches "/repos" and "/repos/x" but
	// not "/reposx"; "/repos/" matches only below it.
	AllowedPathPrefixes []string
	// HeaderName (default Authorization) and HeaderPrefix (for example
	// "Bearer ") shape http_header injection: "<name>: <prefix><secret>".
	HeaderName   string
	HeaderPrefix string
	// QueryParam is the http_query parameter name.
	QueryParam string
	// AllowHTTP permits plain http URLs.
	AllowHTTP bool
	// AllowedCIDRs are private ranges the guarded client may reach for this
	// credential; the caller builds the client from them.
	AllowedCIDRs []netip.Prefix
}

// Request is an agent's brokered HTTP request (POST /v1/agent/http).
type Request struct {
	Credential   string            `json:"credential"`
	Method       string            `json:"method"`
	URL          string            `json:"url"`
	Headers      map[string]string `json:"headers,omitempty"`
	Body         string            `json:"body,omitempty"`
	BodyEncoding string            `json:"bodyEncoding,omitempty"`
	TaskID       string            `json:"taskId,omitempty"`
}

// Response is what the agent gets back.
type Response struct {
	Status       int               `json:"status"`
	Headers      map[string]string `json:"headers"`
	Body         string            `json:"body"`
	BodyEncoding string            `json:"bodyEncoding"`
	Truncated    bool              `json:"truncated"`
	Redacted     bool              `json:"redacted"`
}

// Error is a refused or failed brokered request. Reason is a stable code;
// Message is safe to show the agent (never the secret, never upstream
// error text).
type Error struct {
	Status  int
	Reason  string
	Message string
}

func (e *Error) Error() string { return e.Reason + ": " + e.Message }

func refuse(status int, reason, msg string) *Error {
	return &Error{Status: status, Reason: reason, Message: msg}
}

// Refusal reasons.
const (
	ReasonInvalidRequest      = "invalid_request"
	ReasonMethodNotAllowed    = "method_not_allowed"
	ReasonInvalidURL          = "invalid_url"
	ReasonSchemeNotAllowed    = "scheme_not_allowed"
	ReasonHostNotAllowed      = "host_not_allowed"
	ReasonPathNotAllowed      = "path_not_allowed"
	ReasonInvalidHeader       = "invalid_header"
	ReasonBodyTooLarge        = "body_too_large"
	ReasonKindNotBrokerable   = "kind_not_brokerable"
	ReasonCredentialInvalid   = "credential_invalid"
	ReasonDestinationBlocked  = "destination_blocked"
	ReasonUpstreamTimeout     = "upstream_timeout"
	ReasonUpstreamUnreachable = "upstream_unreachable"
	ReasonUnsupportedEncoding = "unsupported_content_encoding"
)

// Target is a validated destination.
type Target struct {
	URL *url.URL
	// Host is the normalized host (lowercase, no port, IPv6 without
	// brackets); Port is explicit or the scheme default.
	Host string
	Port string
}

// AuditPath is the request path without query string, for audit records.
func (t Target) AuditPath() string {
	if t.URL == nil {
		return ""
	}
	p := t.URL.EscapedPath()
	if p == "" {
		p = "/"
	}
	return p
}

// Prepared is a validated request ready to send.
type Prepared struct {
	Method  string
	Target  Target
	Header  http.Header
	Body    []byte
	profile Profile
}

// Limits bounds a brokered request. Zero values take the defaults.
type Limits struct {
	MaxRequestBody  int64
	MaxResponseBody int64
	MaxRedirects    int
}

func (l Limits) withDefaults() Limits {
	if l.MaxRequestBody <= 0 {
		l.MaxRequestBody = DefaultMaxRequestBody
	}
	if l.MaxResponseBody <= 0 {
		l.MaxResponseBody = DefaultMaxResponseBody
	}
	if l.MaxRedirects < 0 {
		l.MaxRedirects = 0
	} else if l.MaxRedirects == 0 {
		l.MaxRedirects = DefaultMaxRedirects
	}
	return l
}

// Brokerable reports whether a credential kind can be injected.
func Brokerable(kind string) bool {
	switch kind {
	case KindHTTPHeader, KindHTTPBasic, KindHTTPQuery:
		return true
	}
	return false
}

// Prepare validates req against p.
func Prepare(req Request, p Profile, limits Limits) (*Prepared, error) {
	limits = limits.withDefaults()
	if !Brokerable(p.Kind) {
		return nil, refuse(http.StatusBadRequest, ReasonKindNotBrokerable, "this credential cannot be used for HTTP requests")
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	if !brokerMethods[method] {
		return nil, refuse(http.StatusBadRequest, ReasonMethodNotAllowed, "unsupported HTTP method")
	}
	if !methodAllowed(p, method) {
		return nil, refuse(http.StatusForbidden, ReasonMethodNotAllowed, "this credential does not allow that HTTP method")
	}
	target, err := ValidateURL(req.URL, p)
	if err != nil {
		return nil, err
	}
	header, err := agentHeaders(req.Headers, p)
	if err != nil {
		return nil, err
	}
	body, err := decodeBody(req.Body, req.BodyEncoding, limits.MaxRequestBody)
	if err != nil {
		return nil, err
	}
	return &Prepared{Method: method, Target: target, Header: header, Body: body, profile: p}, nil
}

func methodAllowed(p Profile, method string) bool {
	if len(p.AllowedMethods) == 0 {
		return true
	}
	for _, m := range p.AllowedMethods {
		if strings.EqualFold(strings.TrimSpace(m), method) {
			return true
		}
	}
	return false
}

// ValidateURL checks raw against the profile's scheme, host, port and path
// rules.
func ValidateURL(raw string, p Profile) (Target, error) {
	if raw == "" || len(raw) > maxURLLength {
		return Target{}, refuse(http.StatusBadRequest, ReasonInvalidURL, "url must be an absolute URL of at most 8192 characters")
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x21 || raw[i] == 0x7f {
			return Target{}, refuse(http.StatusBadRequest, ReasonInvalidURL, "url must not contain spaces or control characters")
		}
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Opaque != "" {
		return Target{}, refuse(http.StatusBadRequest, ReasonInvalidURL, "url must be an absolute http(s) URL")
	}
	return validateParsed(u, p)
}

func validateParsed(u *url.URL, p Profile) (Target, error) {
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https":
	case "http":
		if !p.AllowHTTP {
			return Target{}, refuse(http.StatusForbidden, ReasonSchemeNotAllowed, "this credential is only sent over https")
		}
	default:
		return Target{}, refuse(http.StatusBadRequest, ReasonInvalidURL, "url must be an absolute http(s) URL")
	}
	if u.User != nil {
		return Target{}, refuse(http.StatusBadRequest, ReasonInvalidURL, "url must not contain credentials")
	}
	if u.Fragment != "" || u.RawFragment != "" {
		u = cloneURL(u)
		u.Fragment, u.RawFragment = "", ""
	}
	host, err := normalizeHost(u.Hostname())
	if err != nil {
		return Target{}, err
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return Target{}, refuse(http.StatusBadRequest, ReasonInvalidURL, "url has an empty port")
	}
	if port == "" {
		port = defaultPort(scheme)
	} else if !validPort(port) {
		return Target{}, refuse(http.StatusBadRequest, ReasonInvalidURL, "url has an invalid port")
	}
	if !hostAllowed(p.AllowedHosts, host, port, scheme) {
		return Target{}, refuse(http.StatusForbidden, ReasonHostNotAllowed, "this credential may not be sent to that host")
	}
	if err := checkPath(u.Path); err != nil {
		return Target{}, err
	}
	if !pathAllowed(p.AllowedPathPrefixes, u.Path) {
		return Target{}, refuse(http.StatusForbidden, ReasonPathNotAllowed, "this credential may not be used for that path")
	}
	out := cloneURL(u)
	out.Scheme = scheme
	if out.Path == "" {
		out.Path, out.RawPath = "/", ""
	}
	return Target{URL: out, Host: host, Port: port}, nil
}

func cloneURL(u *url.URL) *url.URL {
	c := *u
	if u.User != nil {
		uu := *u.User
		c.User = &uu
	}
	return &c
}

func defaultPort(scheme string) string {
	if scheme == "http" {
		return "80"
	}
	return "443"
}

func validPort(p string) bool {
	if len(p) == 0 || len(p) > 5 {
		return false
	}
	n := 0
	for _, c := range p {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n >= 1 && n <= 65535
}

// normalizeHost lowercases a host and strips a trailing dot. Hosts must be
// ASCII: internationalized names are accepted in their punycode (xn--)
// form only, so a look-alike Unicode name can never match an allowed host.
func normalizeHost(h string) (string, error) {
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if h == "" {
		return "", refuse(http.StatusBadRequest, ReasonInvalidURL, "url must include a host")
	}
	if a, err := netip.ParseAddr(h); err == nil {
		if a.Zone() != "" {
			return "", refuse(http.StatusBadRequest, ReasonInvalidURL, "url must not use an IPv6 zone")
		}
		return a.Unmap().String(), nil
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return "", refuse(http.StatusBadRequest, ReasonInvalidURL, "host must be an ASCII name (use the xn-- form for internationalized names) or an IP address")
		}
	}
	if strings.Contains(h, "..") || strings.HasPrefix(h, ".") || len(h) > 253 {
		return "", refuse(http.StatusBadRequest, ReasonInvalidURL, "url has an invalid host")
	}
	return h, nil
}

// splitAllowedHost splits an allowedHosts entry into host and port ("" when
// none).
func splitAllowedHost(entry string) (host, port string) {
	entry = strings.TrimSpace(strings.ToLower(entry))
	if strings.HasPrefix(entry, "[") {
		if i := strings.Index(entry, "]"); i > 0 {
			host = entry[1:i]
			if rest := entry[i+1:]; strings.HasPrefix(rest, ":") {
				port = rest[1:]
			}
			return host, port
		}
	}
	if strings.Count(entry, ":") == 1 {
		h, p, _ := strings.Cut(entry, ":")
		return h, p
	}
	return entry, ""
}

func hostAllowed(allowed []string, host, port, scheme string) bool {
	for _, entry := range allowed {
		h, p := splitAllowedHost(entry)
		h = strings.TrimSuffix(h, ".")
		if p == "" {
			if port != defaultPort(scheme) {
				continue
			}
		} else if p != port {
			continue
		}
		if a, err := netip.ParseAddr(h); err == nil {
			if a.Unmap().String() == host {
				return true
			}
			continue
		}
		if suffix, ok := strings.CutPrefix(h, "*."); ok {
			if suffix != "" && strings.HasSuffix(host, "."+suffix) {
				return true
			}
			continue
		}
		if h == host {
			return true
		}
	}
	return false
}

// checkPath refuses dot segments and backslashes (after percent-decoding),
// which servers may resolve to a path outside an allowed prefix.
func checkPath(p string) error {
	if strings.ContainsAny(p, "\\\x00") {
		return refuse(http.StatusBadRequest, ReasonInvalidURL, "url path must not contain backslashes or NUL")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return refuse(http.StatusBadRequest, ReasonInvalidURL, "url path must not contain . or .. segments")
		}
	}
	return nil
}

func pathAllowed(prefixes []string, p string) bool {
	if len(prefixes) == 0 {
		return true
	}
	if p == "" {
		p = "/"
	}
	for _, prefix := range prefixes {
		prefix = strings.TrimSpace(prefix)
		if prefix == "" {
			continue
		}
		if strings.HasSuffix(prefix, "/") {
			if strings.HasPrefix(p, prefix) {
				return true
			}
			continue
		}
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

// strippedRequestHeaders are agent headers that are never forwarded: the
// credential's own carriers, hop-by-hop and framing headers, and headers
// that would let the agent pose as a proxy or change the response encoding
// (redaction needs an uncompressed body; the transport negotiates gzip
// itself and decodes it).
var strippedRequestHeaders = map[string]bool{
	"Authorization": true, "Proxy-Authorization": true, "Cookie": true, "Cookie2": true,
	"Host": true, "Content-Length": true, "Transfer-Encoding": true, "Connection": true,
	"Keep-Alive": true, "Te": true, "Trailer": true, "Upgrade": true, "Expect": true,
	"Accept-Encoding": true, "Forwarded": true, "Via": true, "X-Real-Ip": true,
	"Proxy-Connection": true, "Http2-Settings": true,
}

func strippedHeader(name string, p Profile) bool {
	if strippedRequestHeaders[name] || strings.HasPrefix(name, "Proxy-") || strings.HasPrefix(name, "X-Forwarded-") {
		return true
	}
	if p.Kind == KindHTTPHeader && name == http.CanonicalHeaderKey(headerName(p)) {
		return true
	}
	return false
}

func headerName(p Profile) string {
	if n := strings.TrimSpace(p.HeaderName); n != "" {
		return n
	}
	return defaultHeaderName
}

func headerPrefix(p Profile) string { return p.HeaderPrefix }

// agentHeaders validates the agent's headers and drops the stripped ones.
func agentHeaders(in map[string]string, p Profile) (http.Header, error) {
	if len(in) > maxHeaders {
		return nil, refuse(http.StatusBadRequest, ReasonInvalidHeader, "too many headers")
	}
	h := http.Header{}
	total := 0
	for name, value := range in {
		total += len(name) + len(value)
		if !validHeaderName(name) {
			return nil, refuse(http.StatusBadRequest, ReasonInvalidHeader, "header names must be HTTP tokens")
		}
		if !validHeaderValue(value) {
			return nil, refuse(http.StatusBadRequest, ReasonInvalidHeader, "header values must not contain control characters")
		}
		canon := http.CanonicalHeaderKey(name)
		if strippedHeader(canon, p) {
			continue
		}
		h.Set(canon, value)
	}
	if total > maxHeaderBytes {
		return nil, refuse(http.StatusBadRequest, ReasonInvalidHeader, "headers are too large")
	}
	return h, nil
}

func validHeaderName(n string) bool {
	if n == "" || len(n) > 256 {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}

func validHeaderValue(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\r' || c == '\n' || c == 0 || (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

func decodeBody(body, encoding string, max int64) ([]byte, error) {
	var b []byte
	switch strings.ToLower(encoding) {
	case "", EncodingText:
		b = []byte(body)
	case EncodingBase64:
		var err error
		b, err = base64.StdEncoding.DecodeString(body)
		if err != nil {
			if b, err = base64.RawStdEncoding.DecodeString(body); err != nil {
				return nil, refuse(http.StatusBadRequest, ReasonInvalidRequest, "body is not valid base64")
			}
		}
	default:
		return nil, refuse(http.StatusBadRequest, ReasonInvalidRequest, "bodyEncoding must be text or base64")
	}
	if int64(len(b)) > max {
		return nil, refuse(http.StatusRequestEntityTooLarge, ReasonBodyTooLarge, "request body exceeds the broker's limit")
	}
	return b, nil
}

// basicSecret is the JSON value of an http_basic credential.
type basicSecret struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// injection is a credential resolved into what goes on the wire.
type injection struct {
	header string // http_header: name
	value  string // http_header: full value
	user   string // http_basic
	pass   string
	param  string // http_query: name
	query  string // http_query: value
}

func resolveInjection(p Profile, secret string) (injection, *Redactor, error) {
	bad := refuse(http.StatusBadGateway, ReasonCredentialInvalid, "the credential's stored value does not fit its kind")
	switch p.Kind {
	case KindHTTPHeader:
		v := headerPrefix(p) + secret
		if secret == "" || !validHeaderValue(v) || !validHeaderName(headerName(p)) {
			return injection{}, nil, bad
		}
		return injection{header: http.CanonicalHeaderKey(headerName(p)), value: v}, NewRedactor(secret), nil
	case KindHTTPBasic:
		var b basicSecret
		dec := json.NewDecoder(strings.NewReader(secret))
		if err := dec.Decode(&b); err != nil || b.Username == "" || strings.Contains(b.Username, ":") ||
			!validHeaderValue(b.Username) || !validHeaderValue(b.Password) {
			return injection{}, nil, bad
		}
		token := base64.StdEncoding.EncodeToString([]byte(b.Username + ":" + b.Password))
		return injection{user: b.Username, pass: b.Password}, NewRedactor(b.Password, b.Username+":"+b.Password, token, secret), nil
	case KindHTTPQuery:
		name := strings.TrimSpace(p.QueryParam)
		if name == "" || secret == "" {
			return injection{}, nil, bad
		}
		return injection{param: name, query: secret}, NewRedactor(secret), nil
	}
	return injection{}, nil, refuse(http.StatusBadRequest, ReasonKindNotBrokerable, "this credential cannot be used for HTTP requests")
}

// Result describes a completed exchange for audit and metrics. It never
// holds secret material.
type Result struct {
	// Target is the last URL requested (after redirects).
	Target        Target
	Method        string
	Status        int
	RequestBytes  int
	ResponseBytes int
	Redirects     int
	Truncated     bool
	Redacted      bool
	Duration      time.Duration
}

// Options configure Do.
type Options struct {
	// Client sends the requests. It must not follow redirects itself and
	// should be SSRF-guarded (see server.newAgentBrokerHTTPClient).
	Client *http.Client
	// IsBlocked reports whether a client error came from the SSRF guard.
	IsBlocked func(error) bool
	Limits    Limits
	// UserAgent is sent when the agent supplied none.
	UserAgent string
}

// Do sends pr with secret injected and returns the filtered, redacted
// response. Errors are *Error. The returned Result is filled as far as the
// exchange got, also on error.
func Do(ctx context.Context, pr *Prepared, secret string, opts Options) (*Response, Result, error) {
	limits := opts.Limits.withDefaults()
	res := Result{Target: pr.Target, Method: pr.Method, RequestBytes: len(pr.Body)}
	start := time.Now()
	defer func() { res.Duration = time.Since(start) }()

	inj, red, err := resolveInjection(pr.profile, secret)
	if err != nil {
		return nil, res, err
	}
	method, target, body := pr.Method, pr.Target, pr.Body
	header := pr.Header.Clone()
	var resp *http.Response
	for {
		req, err := buildRequest(ctx, method, target, header, body, inj, opts.UserAgent)
		if err != nil {
			return nil, res, refuse(http.StatusBadRequest, ReasonInvalidURL, "the request could not be built")
		}
		resp, err = opts.Client.Do(req)
		if err != nil {
			return nil, res, classifyError(ctx, err, opts.IsBlocked)
		}
		res.Target, res.Method, res.Status = target, method, resp.StatusCode
		next, nextMethod, nextBody, ok := followable(resp, method, body, target, pr.profile)
		if !ok || res.Redirects >= limits.MaxRedirects {
			break
		}
		drain(resp)
		res.Redirects++
		if nextMethod != method && nextBody == nil {
			header.Del("Content-Type")
		}
		method, target, body = nextMethod, next, nextBody
	}
	defer resp.Body.Close()

	if ce := strings.TrimSpace(resp.Header.Get("Content-Encoding")); ce != "" && !strings.EqualFold(ce, "identity") {
		return nil, res, refuse(http.StatusBadGateway, ReasonUnsupportedEncoding, "the upstream response used a content encoding the broker cannot inspect")
	}
	limit := limits.MaxResponseBody
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+int64(red.maxFormLen())+1))
	if err != nil {
		return nil, res, classifyError(ctx, err, opts.IsBlocked)
	}
	truncated := int64(len(raw)) > limit
	out, redacted := red.Redact(raw)
	if truncated {
		if t, ok := red.TrimPartial(out); ok {
			out, redacted = t, true
		}
		if int64(len(out)) > limit {
			out = out[:limit]
		}
		if t, ok := red.TrimPartial(out); ok {
			out, redacted = t, true
		}
	}
	headers, hdrRedacted := responseHeaders(resp.Header, red)
	redacted = redacted || hdrRedacted

	r := &Response{Status: resp.StatusCode, Headers: headers, Truncated: truncated, Redacted: redacted}
	if utf8.Valid(out) {
		r.Body, r.BodyEncoding = string(out), EncodingText
	} else {
		r.Body, r.BodyEncoding = base64.StdEncoding.EncodeToString(out), EncodingBase64
	}
	res.ResponseBytes, res.Truncated, res.Redacted = len(out), truncated, redacted
	return r, res, nil
}

func buildRequest(ctx context.Context, method string, t Target, header http.Header, body []byte, inj injection, ua string) (*http.Request, error) {
	u := cloneURL(t.URL)
	if inj.param != "" {
		q := u.Query()
		q.Del(inj.param)
		q.Set(inj.param, inj.query)
		u.RawQuery = q.Encode()
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rdr)
	if err != nil {
		return nil, err
	}
	req.Header = header.Clone()
	if req.Header == nil {
		req.Header = http.Header{}
	}
	if ua != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", ua)
	}
	switch {
	case inj.header != "":
		req.Header.Set(inj.header, inj.value)
	case inj.user != "":
		req.SetBasicAuth(inj.user, inj.pass)
	}
	return req, nil
}

// followable decides whether resp is a redirect the broker follows: to the
// same host and port (an http to https upgrade is fine, a downgrade is
// not), still allowed by the profile.
func followable(resp *http.Response, method string, body []byte, cur Target, p Profile) (Target, string, []byte, bool) {
	switch resp.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
	default:
		return Target{}, "", nil, false
	}
	loc := resp.Header.Get("Location")
	if loc == "" || len(loc) > maxURLLength {
		return Target{}, "", nil, false
	}
	ref, err := url.Parse(loc)
	if err != nil {
		return Target{}, "", nil, false
	}
	next := cur.URL.ResolveReference(ref)
	nextMethod, nextBody := method, body
	if resp.StatusCode == http.StatusSeeOther || (resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound) && method == http.MethodPost {
		if method != http.MethodHead {
			nextMethod = http.MethodGet
		}
		nextBody = nil
	}
	if !methodAllowed(p, nextMethod) {
		return Target{}, "", nil, false
	}
	t, err := validateParsed(next, p)
	if err != nil {
		return Target{}, "", nil, false
	}
	if t.Host != cur.Host {
		return Target{}, "", nil, false
	}
	curScheme, nextScheme := cur.URL.Scheme, t.URL.Scheme
	switch {
	case curScheme == nextScheme:
		if t.Port != cur.Port {
			return Target{}, "", nil, false
		}
	case curScheme == "http" && nextScheme == "https":
		if t.Port != "443" && t.Port != cur.Port {
			return Target{}, "", nil, false
		}
	default:
		return Target{}, "", nil, false
	}
	return t, nextMethod, nextBody, true
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}

// droppedResponseHeaders never reach the agent: cookies and credentials the
// upstream sets, hop-by-hop headers, and framing that no longer matches the
// (decoded, possibly redacted or truncated) body.
var droppedResponseHeaders = map[string]bool{
	"Set-Cookie": true, "Set-Cookie2": true, "Authorization": true, "Proxy-Authorization": true,
	"Proxy-Authenticate": true, "Proxy-Authentication-Info": true, "Authentication-Info": true,
	"Connection": true, "Keep-Alive": true, "Transfer-Encoding": true, "Te": true, "Trailer": true,
	"Upgrade": true, "Proxy-Connection": true, "Content-Length": true, "Content-Encoding": true,
	"Alt-Svc": true,
}

const maxResponseHeaderValue = 8 << 10

func responseHeaders(in http.Header, red *Redactor) (map[string]string, bool) {
	out := make(map[string]string, len(in))
	redacted := false
	for name, values := range in {
		canon := http.CanonicalHeaderKey(name)
		if droppedResponseHeaders[canon] {
			continue
		}
		v := strings.Join(values, ", ")
		if len(v) > maxResponseHeaderValue {
			v = v[:maxResponseHeaderValue]
			if t, ok := red.TrimPartial([]byte(v)); ok {
				v, redacted = string(t), true
			}
		}
		if r, ok := red.RedactString(v); ok {
			v, redacted = r, true
		}
		out[canon] = v
	}
	return out, redacted
}

func classifyError(ctx context.Context, err error, isBlocked func(error) bool) *Error {
	if isBlocked != nil && isBlocked(err) {
		return refuse(http.StatusForbidden, ReasonDestinationBlocked, "the destination resolves to an address this credential may not reach (loopback, link-local, private or metadata)")
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() {
		return refuse(http.StatusGatewayTimeout, ReasonUpstreamTimeout, "the upstream did not respond in time")
	}
	if ctx.Err() != nil {
		return refuse(http.StatusGatewayTimeout, ReasonUpstreamTimeout, "the request was cancelled")
	}
	return refuse(http.StatusBadGateway, ReasonUpstreamUnreachable, "the upstream could not be reached")
}
