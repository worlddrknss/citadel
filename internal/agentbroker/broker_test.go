package agentbroker

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const secret = "s3cr3t-T0ken/with+chars="

func TestRedactorForms(t *testing.T) {
	r := NewRedactor(secret)
	b64 := base64.StdEncoding.EncodeToString([]byte(secret))
	cases := []string{
		secret,
		b64,
		strings.TrimRight(b64, "="),
		base64.URLEncoding.EncodeToString([]byte(secret)),
		base64.RawURLEncoding.EncodeToString([]byte(secret)),
		url.QueryEscape(secret),
		lowerPercentHex(url.QueryEscape(secret)),
		url.PathEscape(secret),
		`s3cr3t-T0ken\/with+chars=`[:0] + "s3cr3t-T0ken/with+chars=",
	}
	for _, c := range cases {
		in := "before " + c + " after"
		out, changed := r.RedactString(in)
		if !changed || strings.Contains(out, c) || out != "before "+Redacted+" after" {
			t.Errorf("form %q: got %q changed=%v", c, out, changed)
		}
	}
	// JSON escaping of a secret with quotes and control characters.
	q := NewRedactor(`pa"ss\word`)
	if out, ok := q.RedactString(`{"v":"pa\"ss\\word"}`); !ok || out != `{"v":"`+Redacted+`"}` {
		t.Errorf("json form: %q %v", out, ok)
	}
	if out, ok := r.RedactString("nothing here"); ok || out != "nothing here" {
		t.Errorf("clean text changed: %q", out)
	}
	if out, ok := NewRedactor("abc").RedactString("abcabc"); ok || out != "abcabc" {
		t.Errorf("short secret redacted: %q", out)
	}
	if out, _ := r.RedactString(secret + secret); out != Redacted+Redacted {
		t.Errorf("adjacent occurrences: %q", out)
	}
}

func TestRedactorTrimPartial(t *testing.T) {
	r := NewRedactor(secret)
	for _, k := range []int{1, 5, len(secret) - 1} {
		in := []byte("data " + secret[:k])
		out, ok := r.TrimPartial(in)
		if !ok || string(out) != "data " {
			t.Errorf("k=%d: %q %v", k, out, ok)
		}
	}
	if out, ok := r.TrimPartial([]byte("data xyz")); ok || string(out) != "data xyz" {
		t.Errorf("unrelated tail trimmed: %q", out)
	}
}

func profile(kind string, hosts ...string) Profile {
	return Profile{Kind: kind, AllowedHosts: hosts, HeaderName: "Authorization", HeaderPrefix: "Bearer ", QueryParam: "api_key"}
}

func TestValidateURL(t *testing.T) {
	p := Profile{Kind: KindHTTPHeader, AllowedHosts: []string{"api.example.com", "*.svc.example.com", "alt.example.com:8443", "10.0.0.5", "[2001:db8::1]:8080"}}
	ok := []string{
		"https://api.example.com/",
		"https://API.Example.COM./x",
		"https://api.example.com:443/x?y=1",
		"https://a.svc.example.com/",
		"https://a.b.svc.example.com/",
		"https://alt.example.com:8443/",
		"https://10.0.0.5/",
		"https://[2001:db8::1]:8080/",
		"https://api.example.com/x#frag",
	}
	for _, u := range ok {
		if _, err := ValidateURL(u, p); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	bad := map[string]string{
		"http://api.example.com/":                              ReasonSchemeNotAllowed,
		"ftp://api.example.com/":                               ReasonInvalidURL,
		"https://user:pw@api.example.com/":                     ReasonInvalidURL,
		"https://evil.com/":                                    ReasonHostNotAllowed,
		"https://api.example.com.evil.com/":                    ReasonHostNotAllowed,
		"https://svc.example.com/":                             ReasonHostNotAllowed,
		"https://api.example.com:8443/":                        ReasonHostNotAllowed,
		"https://alt.example.com/":                             ReasonHostNotAllowed,
		"https://10.0.0.6/":                                    ReasonHostNotAllowed,
		"https://[2001:db8::1]/":                               ReasonHostNotAllowed,
		"https://api.example.com/a/../b":                       ReasonInvalidURL,
		"https://api.example.com/a/%2e%2e/b":                   ReasonInvalidURL,
		"https://api.example.com/a\\b":                         ReasonInvalidURL,
		"https://xn--pple-43d.com/":                            ReasonHostNotAllowed,
		"https://аpple.com/":                                   ReasonInvalidURL,
		"/relative":                                            ReasonInvalidURL,
		"https://api.example.com/ x":                           ReasonInvalidURL,
		"https://api.example.com:0/":                           ReasonInvalidURL,
		"https://api.example.com:/":                            ReasonInvalidURL,
		"https://[fe80::1%25eth0]/":                            ReasonInvalidURL,
		"https://api.example.com/\x00":                         ReasonInvalidURL,
		"":                                                     ReasonInvalidURL,
		"https://api.example.com/" + strings.Repeat("a", 9000): ReasonInvalidURL,
	}
	for u, reason := range bad {
		_, err := ValidateURL(u, p)
		var e *Error
		if !errors.As(err, &e) || e.Reason != reason {
			t.Errorf("%q: err=%v, want %s", u, err, reason)
		}
	}
	p.AllowHTTP = true
	if _, err := ValidateURL("http://api.example.com/", p); err != nil {
		t.Errorf("http with AllowHTTP: %v", err)
	}
	if _, err := ValidateURL("http://api.example.com:443/", p); err == nil {
		t.Error("http on 443 matched a port-less entry")
	}
}

func TestPathPrefixes(t *testing.T) {
	p := Profile{Kind: KindHTTPHeader, AllowedHosts: []string{"api.example.com"}, AllowedPathPrefixes: []string{"/repos", "/user/"}}
	for path, want := range map[string]bool{
		"/repos": true, "/repos/a": true, "/reposx": false, "/user/": true, "/user/x": true, "/user": false,
		"/": false, "/admin": false, "/repos%2F..%2Fadmin": false,
	} {
		_, err := ValidateURL("https://api.example.com"+path, p)
		if (err == nil) != want {
			t.Errorf("%s: err=%v, want allowed=%v", path, err, want)
		}
	}
}

func TestPrepareMethodsHeadersBody(t *testing.T) {
	p := profile(KindHTTPHeader, "api.example.com")
	p.AllowedMethods = []string{"get", "POST"}
	if _, err := Prepare(Request{Method: "DELETE", URL: "https://api.example.com/"}, p, Limits{}); reason(err) != ReasonMethodNotAllowed {
		t.Errorf("DELETE: %v", err)
	}
	if _, err := Prepare(Request{Method: "TRACE", URL: "https://api.example.com/"}, Profile{Kind: KindHTTPHeader, AllowedHosts: []string{"api.example.com"}}, Limits{}); reason(err) != ReasonMethodNotAllowed {
		t.Errorf("TRACE: %v", err)
	}
	pr, err := Prepare(Request{URL: "https://api.example.com/"}, p, Limits{})
	if err != nil || pr.Method != http.MethodGet {
		t.Fatalf("default method: %v %v", pr, err)
	}
	pr, err = Prepare(Request{Method: "post", URL: "https://api.example.com/", Headers: map[string]string{
		"authorization": "Bearer agent", "Cookie": "a=b", "Proxy-Authorization": "x", "Proxy-Foo": "x",
		"X-Forwarded-For": "1.2.3.4", "Host": "evil.com", "Accept-Encoding": "br", "Content-Length": "5",
		"Accept": "application/json", "X-Custom": "v",
	}, Body: "aGVsbG8=", BodyEncoding: "base64"}, p, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(pr.Header) != 2 || pr.Header.Get("Accept") != "application/json" || pr.Header.Get("X-Custom") != "v" {
		t.Errorf("headers not stripped: %v", pr.Header)
	}
	if string(pr.Body) != "hello" {
		t.Errorf("body %q", pr.Body)
	}
	for _, h := range []map[string]string{{"Bad Name": "v"}, {"X": "a\r\nInjected: 1"}, {"X": "a\x00"}} {
		if _, err := Prepare(Request{URL: "https://api.example.com/", Headers: h}, p, Limits{}); reason(err) != ReasonInvalidHeader {
			t.Errorf("%v: %v", h, err)
		}
	}
	custom := Profile{Kind: KindHTTPHeader, AllowedHosts: []string{"api.example.com"}, HeaderName: "X-Api-Key"}
	pr, _ = Prepare(Request{URL: "https://api.example.com/", Headers: map[string]string{"x-api-key": "agent", "Authorization": "x"}}, custom, Limits{})
	if len(pr.Header) != 0 {
		t.Errorf("credential header not stripped: %v", pr.Header)
	}
	if _, err := Prepare(Request{URL: "https://api.example.com/", Body: strings.Repeat("a", 11)}, p, Limits{MaxRequestBody: 10}); reason(err) != ReasonBodyTooLarge {
		t.Errorf("body cap: %v", err)
	}
	if _, err := Prepare(Request{URL: "https://api.example.com/", Body: "!!", BodyEncoding: "base64"}, p, Limits{}); reason(err) != ReasonInvalidRequest {
		t.Errorf("bad base64: %v", err)
	}
	if _, err := Prepare(Request{URL: "https://api.example.com/"}, Profile{Kind: "raw", AllowedHosts: []string{"api.example.com"}}, Limits{}); reason(err) != ReasonKindNotBrokerable {
		t.Errorf("raw kind: %v", err)
	}
}

func reason(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

// upstream records what the broker sent.
type upstream struct {
	srv  *httptest.Server
	host string
	last *http.Request
	body []byte
}

func newUpstream(t *testing.T, h http.HandlerFunc) *upstream {
	u := &upstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.last = r.Clone(context.Background())
		u.body, _ = io.ReadAll(r.Body)
		h(w, r)
	}))
	t.Cleanup(u.srv.Close)
	u.host = strings.TrimPrefix(u.srv.URL, "http://")
	return u
}

func plainClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func do(t *testing.T, req Request, p Profile, sec string, limits Limits) (*Response, Result, error) {
	t.Helper()
	pr, err := Prepare(req, p, limits)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	return Do(context.Background(), pr, sec, Options{Client: plainClient(), Limits: limits, UserAgent: "citadel-test"})
}

func TestInjection(t *testing.T) {
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })

	p := profile(KindHTTPHeader, up.host)
	p.AllowHTTP = true
	if _, _, err := do(t, Request{URL: up.srv.URL + "/x", Headers: map[string]string{"Authorization": "Bearer agent-supplied"}}, p, secret, Limits{}); err != nil {
		t.Fatal(err)
	}
	if got := up.last.Header.Values("Authorization"); len(got) != 1 || got[0] != "Bearer "+secret {
		t.Errorf("header injection: %v", got)
	}
	if up.last.Header.Get("User-Agent") != "citadel-test" {
		t.Errorf("user agent: %q", up.last.Header.Get("User-Agent"))
	}

	custom := Profile{Kind: KindHTTPHeader, AllowedHosts: []string{up.host}, AllowHTTP: true, HeaderName: "X-Api-Key"}
	if _, _, err := do(t, Request{URL: up.srv.URL, Headers: map[string]string{"X-API-KEY": "agent"}}, custom, secret, Limits{}); err != nil {
		t.Fatal(err)
	}
	if got := up.last.Header.Values("X-Api-Key"); len(got) != 1 || got[0] != secret {
		t.Errorf("custom header: %v", got)
	}

	basic := Profile{Kind: KindHTTPBasic, AllowedHosts: []string{up.host}, AllowHTTP: true}
	if _, _, err := do(t, Request{URL: up.srv.URL}, basic, `{"username":"bot","password":"hunter2-long"}`, Limits{}); err != nil {
		t.Fatal(err)
	}
	if u, pw, ok := up.last.BasicAuth(); !ok || u != "bot" || pw != "hunter2-long" {
		t.Errorf("basic: %q %q %v", u, pw, ok)
	}
	pr, _ := Prepare(Request{URL: up.srv.URL}, basic, Limits{})
	if _, _, err := Do(context.Background(), pr, "not json", Options{Client: plainClient()}); reason(err) != ReasonCredentialInvalid {
		t.Errorf("bad basic secret: %v", err)
	}

	query := Profile{Kind: KindHTTPQuery, AllowedHosts: []string{up.host}, AllowHTTP: true, QueryParam: "api_key"}
	if _, _, err := do(t, Request{URL: up.srv.URL + "/q?api_key=agent&x=1"}, query, secret, Limits{}); err != nil {
		t.Fatal(err)
	}
	if got := up.last.URL.Query()["api_key"]; len(got) != 1 || got[0] != secret || up.last.URL.Query().Get("x") != "1" {
		t.Errorf("query injection: %v", up.last.URL.Query())
	}

	pr, _ = Prepare(Request{URL: up.srv.URL}, p, Limits{})
	if _, _, err := Do(context.Background(), pr, "bad\r\nvalue", Options{Client: plainClient()}); reason(err) != ReasonCredentialInvalid {
		t.Errorf("header secret with CRLF: %v", err)
	}
}

func TestResponseRedactionAndHeaders(t *testing.T) {
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "session=abc")
		w.Header().Set("WWW-Authenticate", `Bearer realm="api"`)
		w.Header().Set("X-Echo", "Bearer "+secret)
		w.Header().Set("Authorization", "x")
		w.Header().Add("X-Multi", "a")
		w.Header().Add("X-Multi", "b")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"auth":"` + r.Header.Get("Authorization") + `","b64":"` + base64.StdEncoding.EncodeToString([]byte(secret)) + `"}`))
	})
	p := profile(KindHTTPHeader, up.host)
	p.AllowHTTP = true
	resp, res, err := do(t, Request{URL: up.srv.URL}, p, secret, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(resp.Body, secret) || strings.Contains(resp.Body, base64.StdEncoding.EncodeToString([]byte(secret))) {
		t.Fatalf("secret leaked in body: %s", resp.Body)
	}
	if !resp.Redacted || !res.Redacted || resp.Body != `{"auth":"Bearer [REDACTED]","b64":"[REDACTED]"}` {
		t.Errorf("body: %s redacted=%v", resp.Body, resp.Redacted)
	}
	if _, ok := resp.Headers["Set-Cookie"]; ok {
		t.Error("Set-Cookie passed through")
	}
	if _, ok := resp.Headers["Authorization"]; ok {
		t.Error("Authorization passed through")
	}
	if resp.Headers["Www-Authenticate"] != `Bearer realm="api"` {
		t.Errorf("WWW-Authenticate: %q", resp.Headers["Www-Authenticate"])
	}
	if resp.Headers["X-Echo"] != "Bearer [REDACTED]" || resp.Headers["X-Multi"] != "a, b" {
		t.Errorf("headers: %v", resp.Headers)
	}
	if resp.Status != 200 || resp.BodyEncoding != EncodingText || res.Status != 200 {
		t.Errorf("status/encoding: %d %s", resp.Status, resp.BodyEncoding)
	}
}

func TestBinaryAndGzipResponses(t *testing.T) {
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bin":
			_, _ = w.Write([]byte{0xff, 0xfe, 0x00, 0x01})
		case "/gzip":
			if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				_, _ = w.Write([]byte("plain"))
				return
			}
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			_, _ = gz.Write([]byte("zipped " + secret))
			_ = gz.Close()
		case "/br":
			w.Header().Set("Content-Encoding", "br")
			_, _ = w.Write([]byte("opaque"))
		}
	})
	p := profile(KindHTTPHeader, up.host)
	p.AllowHTTP = true
	resp, _, err := do(t, Request{URL: up.srv.URL + "/bin"}, p, secret, Limits{})
	if err != nil || resp.BodyEncoding != EncodingBase64 || resp.Body != base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe, 0x00, 0x01}) {
		t.Errorf("binary: %+v %v", resp, err)
	}
	resp, _, err = do(t, Request{URL: up.srv.URL + "/gzip", Headers: map[string]string{"Accept-Encoding": "br"}}, p, secret, Limits{})
	if err != nil || resp.Body != "zipped [REDACTED]" {
		t.Errorf("gzip: %+v %v", resp, err)
	}
	if _, _, err := do(t, Request{URL: up.srv.URL + "/br"}, p, secret, Limits{}); reason(err) != ReasonUnsupportedEncoding {
		t.Errorf("br: %v", err)
	}
}

func TestResponseTruncation(t *testing.T) {
	const limit = 1000
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			_, _ = w.Write(bytes.Repeat([]byte("a"), 5000))
		case "/boundary":
			// The secret straddles the limit.
			_, _ = w.Write([]byte(strings.Repeat("a", limit-5) + secret + strings.Repeat("b", 100)))
		case "/exact":
			_, _ = w.Write(bytes.Repeat([]byte("a"), limit))
		}
	})
	p := profile(KindHTTPHeader, up.host)
	p.AllowHTTP = true
	resp, res, err := do(t, Request{URL: up.srv.URL + "/big"}, p, secret, Limits{MaxResponseBody: limit})
	if err != nil || !resp.Truncated || len(resp.Body) != limit || !res.Truncated || res.ResponseBytes != limit {
		t.Errorf("big: truncated=%v len=%d err=%v", resp.Truncated, len(resp.Body), err)
	}
	resp, _, err = do(t, Request{URL: up.srv.URL + "/boundary"}, p, secret, Limits{MaxResponseBody: limit})
	if err != nil || !resp.Truncated {
		t.Fatalf("boundary: %v", err)
	}
	for k := 4; k <= len(secret); k++ {
		if strings.Contains(resp.Body, secret[:k]) {
			t.Fatalf("partial secret (%d chars) leaked at the truncation boundary: ...%s", k, resp.Body[len(resp.Body)-20:])
		}
	}
	resp, _, err = do(t, Request{URL: up.srv.URL + "/exact"}, p, secret, Limits{MaxResponseBody: limit})
	if err != nil || resp.Truncated || len(resp.Body) != limit {
		t.Errorf("exact: truncated=%v len=%d err=%v", resp.Truncated, len(resp.Body), err)
	}
}

func TestRedirects(t *testing.T) {
	other := newUpstream(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("other")) })
	var up *upstream
	up = newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/r1":
			http.Redirect(w, r, "/r2", http.StatusFound)
		case "/r2":
			http.Redirect(w, r, up.srv.URL+"/final", http.StatusMovedPermanently)
		case "/final":
			_, _ = w.Write([]byte("final " + r.Method + " " + r.URL.Query().Get("api_key")))
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		case "/cross":
			http.Redirect(w, r, other.srv.URL+"/x", http.StatusFound)
		case "/see-other":
			http.Redirect(w, r, "/final", http.StatusSeeOther)
		case "/temp":
			http.Redirect(w, r, "/echo", http.StatusTemporaryRedirect)
		case "/echo":
			_, _ = w.Write([]byte(r.Method + ":" + string(up.body)))
		case "/outside":
			http.Redirect(w, r, "/admin", http.StatusFound)
		}
	})
	p := Profile{Kind: KindHTTPQuery, QueryParam: "api_key", AllowedHosts: []string{up.host, other.host}, AllowHTTP: true}

	resp, res, err := do(t, Request{URL: up.srv.URL + "/r1"}, p, secret, Limits{})
	if err != nil || resp.Status != 200 || resp.Body != "final GET [REDACTED]" || res.Redirects != 2 || res.Target.AuditPath() != "/final" {
		t.Errorf("same-host chain: %+v %+v %v", resp, res, err)
	}
	resp, res, err = do(t, Request{URL: up.srv.URL + "/loop"}, p, secret, Limits{})
	if err != nil || resp.Status != http.StatusFound || res.Redirects != 3 {
		t.Errorf("loop: status=%d redirects=%d err=%v", resp.Status, res.Redirects, err)
	}
	resp, _, err = do(t, Request{URL: up.srv.URL + "/cross"}, p, secret, Limits{})
	if err != nil || resp.Status != http.StatusFound {
		t.Errorf("cross-host was followed: %+v %v", resp, err)
	}
	if other.last != nil {
		t.Error("cross-host redirect reached the other host")
	}
	if !strings.HasPrefix(resp.Headers["Location"], other.srv.URL) {
		t.Errorf("Location not returned: %v", resp.Headers)
	}
	resp, _, _ = do(t, Request{Method: "POST", URL: up.srv.URL + "/see-other", Body: "data"}, p, secret, Limits{})
	if resp.Body != "final GET [REDACTED]" {
		t.Errorf("303: %q", resp.Body)
	}
	resp, _, _ = do(t, Request{Method: "POST", URL: up.srv.URL + "/temp", Body: "data"}, p, secret, Limits{})
	if resp.Body != "POST:data" {
		t.Errorf("307: %q", resp.Body)
	}
	limited := p
	limited.AllowedPathPrefixes = []string{"/outside", "/final"}
	resp, _, _ = do(t, Request{URL: up.srv.URL + "/outside"}, limited, secret, Limits{})
	if resp.Status != http.StatusFound {
		t.Errorf("redirect outside the allowed paths was followed: %d", resp.Status)
	}
}

func TestRedirectDowngradeRefused(t *testing.T) {
	cur, _ := ValidateURL("https://api.example.com/a", Profile{Kind: KindHTTPHeader, AllowedHosts: []string{"api.example.com"}, AllowHTTP: true})
	p := Profile{Kind: KindHTTPHeader, AllowedHosts: []string{"api.example.com"}, AllowHTTP: true}
	resp := &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {"http://api.example.com/b"}}}
	if _, _, _, ok := followable(resp, "GET", nil, cur, p); ok {
		t.Error("https to http downgrade followed")
	}
	cur, _ = ValidateURL("http://api.example.com/a", p)
	resp.Header.Set("Location", "https://api.example.com/b")
	if _, _, _, ok := followable(resp, "GET", nil, cur, p); !ok {
		t.Error("http to https upgrade not followed")
	}
}

func TestUpstreamErrors(t *testing.T) {
	p := Profile{Kind: KindHTTPHeader, AllowedHosts: []string{"127.0.0.1:1"}, AllowHTTP: true}
	pr, err := Prepare(Request{URL: "http://127.0.0.1:1/"}, p, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	blocked := errors.New("blocked")
	_, _, err = Do(context.Background(), pr, secret, Options{Client: plainClient()})
	if reason(err) != ReasonUpstreamUnreachable {
		t.Errorf("refused: %v", err)
	}
	failing := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, blocked })}
	_, _, err = Do(context.Background(), pr, secret, Options{Client: failing, IsBlocked: func(e error) bool { return errors.Is(e, blocked) }})
	if reason(err) != ReasonDestinationBlocked {
		t.Errorf("blocked: %v", err)
	}
	slow := newUpstream(t, func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond) })
	sp := Profile{Kind: KindHTTPHeader, AllowedHosts: []string{slow.host}, AllowHTTP: true}
	pr, _ = Prepare(Request{URL: slow.srv.URL}, sp, Limits{})
	_, _, err = Do(context.Background(), pr, secret, Options{Client: &http.Client{Timeout: 50 * time.Millisecond}})
	if reason(err) != ReasonUpstreamTimeout {
		t.Errorf("timeout: %v", err)
	}
	if e := (&Error{Reason: "x", Message: "y"}); e.Error() != "x: y" {
		t.Error(e.Error())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
