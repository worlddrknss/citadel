package agentbroker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

// Redacted replaces every secret occurrence found in upstream responses.
const Redacted = "[REDACTED]"

// minRedactLen is the shortest secret form that is redacted. Shorter values
// would match ordinary text all over a response; such secrets should not be
// brokered in the first place.
const minRedactLen = 4

// Redactor replaces a secret and its common encodings (base64, base64url,
// URL query and path escaping, JSON string escaping, hex-case variants of
// percent escapes) with Redacted.
type Redactor struct {
	forms [][]byte // longest first, so a longer form wins over its substrings
}

// NewRedactor returns a Redactor for secrets. Empty and very short values
// are ignored.
func NewRedactor(secrets ...string) *Redactor {
	seen := map[string]bool{}
	var forms [][]byte
	add := func(v string) {
		if len(v) < minRedactLen || seen[v] {
			return
		}
		seen[v] = true
		forms = append(forms, []byte(v))
	}
	for _, s := range secrets {
		if len(s) < minRedactLen {
			continue
		}
		add(s)
		b := []byte(s)
		add(base64.StdEncoding.EncodeToString(b))
		add(base64.RawStdEncoding.EncodeToString(b))
		add(base64.URLEncoding.EncodeToString(b))
		add(base64.RawURLEncoding.EncodeToString(b))
		for _, esc := range []string{url.QueryEscape(s), url.PathEscape(s), strings.ReplaceAll(url.QueryEscape(s), "+", "%20")} {
			add(esc)
			add(lowerPercentHex(esc))
		}
		if j, err := json.Marshal(s); err == nil && len(j) >= 2 {
			add(string(j[1 : len(j)-1]))
		}
	}
	sort.SliceStable(forms, func(i, j int) bool { return len(forms[i]) > len(forms[j]) })
	return &Redactor{forms: forms}
}

// lowerPercentHex lowercases the hex digits of percent escapes.
func lowerPercentHex(s string) string {
	b := []byte(s)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' {
			b[i+1] = lowerHex(b[i+1])
			b[i+2] = lowerHex(b[i+2])
		}
	}
	return string(b)
}

func lowerHex(c byte) byte {
	if c >= 'A' && c <= 'F' {
		return c + ('a' - 'A')
	}
	return c
}

// maxFormLen is the length of the longest form (0 when there is none).
func (r *Redactor) maxFormLen() int {
	if r == nil || len(r.forms) == 0 {
		return 0
	}
	return len(r.forms[0])
}

// Redact returns b with every form replaced and whether anything was.
func (r *Redactor) Redact(b []byte) ([]byte, bool) {
	if r == nil || len(r.forms) == 0 || len(b) == 0 {
		return b, false
	}
	var out bytes.Buffer
	changed := false
	i := 0
	for i < len(b) {
		matched := 0
		for _, f := range r.forms {
			if len(b)-i >= len(f) && b[i] == f[0] && bytes.Equal(b[i:i+len(f)], f) {
				matched = len(f)
				break
			}
		}
		if matched > 0 {
			if !changed {
				out.Grow(len(b))
				out.Write(b[:i])
				changed = true
			}
			out.WriteString(Redacted)
			i += matched
			continue
		}
		if changed {
			out.WriteByte(b[i])
		}
		i++
	}
	if !changed {
		return b, false
	}
	return out.Bytes(), true
}

// RedactString is Redact for strings.
func (r *Redactor) RedactString(s string) (string, bool) {
	out, changed := r.Redact([]byte(s))
	if !changed {
		return s, false
	}
	return string(out), true
}

// TrimPartial removes a trailing fragment of b that is the beginning of a
// secret form: what is left when a body is cut off in the middle of a
// secret. It reports whether anything was removed.
func (r *Redactor) TrimPartial(b []byte) ([]byte, bool) {
	if r == nil {
		return b, false
	}
	cut := 0
	for _, f := range r.forms {
		max := len(f) - 1
		if max > len(b) {
			max = len(b)
		}
		for k := max; k > cut; k-- {
			if bytes.HasSuffix(b, f[:k]) {
				cut = k
				break
			}
		}
	}
	if cut == 0 {
		return b, false
	}
	return b[:len(b)-cut], true
}
