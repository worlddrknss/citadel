package server

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// parseYAMLSubset parses the YAML subset docs/openapi.yaml is written in
// (see the header comment there): block mappings and sequences with spaces,
// plain and quoted scalars, `|` literal blocks, flow `[]`, `{}` and one-line
// lists of scalars, and full-line comments. The repository takes no YAML
// dependency, and the console's viewer parses the same subset
// (web/src/lib/yaml.ts), so the drift test also keeps the document inside it.
func parseYAMLSubset(src string) (any, error) {
	p := &yamlParser{lines: strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")}
	for i, ln := range p.lines {
		if strings.Contains(ln, "\t") {
			return nil, fmt.Errorf("line %d: tabs are not allowed", i+1)
		}
	}
	p.skip()
	if p.pos >= len(p.lines) {
		return nil, nil
	}
	v, err := p.node(indentOf(p.lines[p.pos]))
	if err != nil {
		return nil, err
	}
	p.skip()
	if p.pos < len(p.lines) {
		return nil, fmt.Errorf("line %d: unexpected content", p.pos+1)
	}
	return v, nil
}

type yamlParser struct {
	lines []string
	pos   int
}

func indentOf(s string) int { return len(s) - len(strings.TrimLeft(s, " ")) }

func isBlankOrComment(s string) bool {
	t := strings.TrimSpace(s)
	return t == "" || strings.HasPrefix(t, "#")
}

// skip advances past blank and comment lines.
func (p *yamlParser) skip() {
	for p.pos < len(p.lines) && isBlankOrComment(p.lines[p.pos]) {
		p.pos++
	}
}

func isSeqLine(t string) bool { return t == "-" || strings.HasPrefix(t, "- ") }

func (p *yamlParser) node(indent int) (any, error) {
	p.skip()
	if isSeqLine(strings.TrimSpace(p.lines[p.pos])) {
		return p.seq(indent)
	}
	return p.mapping(indent)
}

func (p *yamlParser) errf(format string, a ...any) error {
	return fmt.Errorf("line %d: %s", p.pos+1, fmt.Sprintf(format, a...))
}

func (p *yamlParser) mapping(indent int) (any, error) {
	out := map[string]any{}
	for {
		p.skip()
		if p.pos >= len(p.lines) {
			return out, nil
		}
		ln := p.lines[p.pos]
		ind := indentOf(ln)
		if ind < indent {
			return out, nil
		}
		if ind > indent {
			return nil, p.errf("unexpected indentation")
		}
		t := strings.TrimSpace(ln)
		if isSeqLine(t) {
			return out, nil
		}
		key, rest, err := splitKey(t)
		if err != nil {
			return nil, p.errf("%v", err)
		}
		if _, dup := out[key]; dup {
			return nil, p.errf("duplicate key %q", key)
		}
		p.pos++
		v, err := p.value(indent, rest, true)
		if err != nil {
			return nil, err
		}
		out[key] = v
	}
}

// value parses what follows "key:" or "- ": an inline scalar, a literal
// block, or a nested block node.
func (p *yamlParser) value(indent int, rest string, inMapping bool) (any, error) {
	switch rest {
	case "|", "|-":
		return p.literal(indent, rest == "|-"), nil
	case "":
		p.skip()
		if p.pos >= len(p.lines) {
			return nil, nil
		}
		next := p.lines[p.pos]
		ni := indentOf(next)
		if ni > indent {
			return p.node(ni)
		}
		if inMapping && ni == indent && isSeqLine(strings.TrimSpace(next)) {
			return p.seq(indent)
		}
		return nil, nil
	}
	return parseScalar(rest)
}

func (p *yamlParser) literal(indent int, strip bool) string {
	var body []string
	block := -1
	for p.pos < len(p.lines) {
		ln := p.lines[p.pos]
		if strings.TrimSpace(ln) == "" {
			body = append(body, "")
			p.pos++
			continue
		}
		ind := indentOf(ln)
		if ind <= indent {
			break
		}
		if block < 0 {
			block = ind
		}
		if ind < block {
			break
		}
		body = append(body, ln[block:])
		p.pos++
	}
	for len(body) > 0 && body[len(body)-1] == "" {
		body = body[:len(body)-1]
	}
	s := strings.Join(body, "\n")
	if !strip && s != "" {
		s += "\n"
	}
	return s
}

func (p *yamlParser) seq(indent int) (any, error) {
	out := []any{}
	for {
		p.skip()
		if p.pos >= len(p.lines) {
			return out, nil
		}
		ln := p.lines[p.pos]
		ind := indentOf(ln)
		t := strings.TrimSpace(ln)
		if ind < indent || (ind == indent && !isSeqLine(t)) {
			return out, nil
		}
		if ind > indent {
			return nil, p.errf("unexpected indentation")
		}
		item := strings.TrimPrefix(strings.TrimPrefix(t, "-"), " ")
		if item == "" {
			p.pos++
			v, err := p.value(indent, "", false)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}
		if isMappingItem(item) {
			// "- key: value": a mapping whose keys sit at indent+2.
			p.lines[p.pos] = strings.Repeat(" ", indent+2) + item
			v, err := p.mapping(indent + 2)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}
		p.pos++
		v, err := parseScalar(item)
		if err != nil {
			return nil, p.errf("%v", err)
		}
		out = append(out, v)
	}
}

// isMappingItem reports whether a sequence item ("- <item>") starts a
// mapping rather than being a scalar.
func isMappingItem(item string) bool {
	switch item[0] {
	case '"':
		end := closingQuote(item)
		return end > 0 && strings.HasPrefix(item[end+1:], ":")
	case '\'', '[', '{':
		return false
	}
	_, _, err := splitKey(item)
	return err == nil
}

// closingQuote returns the index of the quote closing the double-quoted
// string at the start of s, or -1.
func closingQuote(s string) int {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i
		}
	}
	return -1
}

// splitKey splits "key: rest" (or "key:") into its key and the trimmed rest.
func splitKey(t string) (string, string, error) {
	if strings.HasPrefix(t, "\"") {
		end := closingQuote(t)
		if end < 0 || !strings.HasPrefix(t[end+1:], ":") {
			return "", "", fmt.Errorf("bad quoted key")
		}
		var k string
		if err := json.Unmarshal([]byte(t[:end+1]), &k); err != nil {
			return "", "", fmt.Errorf("bad quoted key: %v", err)
		}
		rest := t[end+2:]
		if rest != "" && !strings.HasPrefix(rest, " ") {
			return "", "", fmt.Errorf("expected space after colon")
		}
		return k, strings.TrimSpace(rest), nil
	}
	if i := strings.Index(t, ": "); i > 0 {
		return t[:i], strings.TrimSpace(t[i+2:]), nil
	}
	if strings.HasSuffix(t, ":") && len(t) > 1 {
		return t[:len(t)-1], "", nil
	}
	return "", "", fmt.Errorf("expected key: value")
}

func parseScalar(s string) (any, error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "\""):
		var v string
		if closingQuote(s) != len(s)-1 {
			return nil, fmt.Errorf("unterminated or trailing content after quoted string")
		}
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			return nil, fmt.Errorf("bad quoted string: %v", err)
		}
		return v, nil
	case strings.HasPrefix(s, "'"):
		if len(s) < 2 || !strings.HasSuffix(s, "'") {
			return nil, fmt.Errorf("unterminated single-quoted string")
		}
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'"), nil
	case s == "{}":
		return map[string]any{}, nil
	case strings.HasPrefix(s, "{"):
		return nil, fmt.Errorf("flow mappings are not supported")
	case strings.HasPrefix(s, "["):
		if !strings.HasSuffix(s, "]") {
			return nil, fmt.Errorf("unterminated flow sequence")
		}
		inner := strings.TrimSpace(s[1 : len(s)-1])
		out := []any{}
		if inner == "" {
			return out, nil
		}
		for _, part := range strings.Split(inner, ",") {
			part = strings.TrimSpace(part)
			if part == "" || strings.ContainsAny(part[:1], "[{") {
				return nil, fmt.Errorf("unsupported flow sequence item %q", part)
			}
			v, err := parseScalar(part)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case strings.ContainsAny(s[:1], "&*!|>%@`"):
		return nil, fmt.Errorf("unsupported scalar %q", s)
	case strings.Contains(s, " #"):
		return nil, fmt.Errorf("inline comments are not supported")
	}
	switch s {
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "null", "~":
		return nil, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && strings.ContainsAny(s, "0123456789") {
		return f, nil
	}
	return s, nil
}

func TestParseYAMLSubset(t *testing.T) {
	src := `# comment
openapi: 3.1.0
info:
  title: "A: title"
  description: |
    Line one.

    Line two.
  version: 2
tags: [A, "B C", 'd''s']
empty: []
obj: {}
list:
  - name: x
    in: query
    schema:
      type: string
  - plain
  -
    nested: true
seqAtKeyIndent:
- one
- "two"
paths:
  /v1/x:
    get:
      responses:
        "200":
          description: ok
`
	got, err := parseYAMLSubset(src)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"openapi": "3.1.0",
		"info":    map[string]any{"title": "A: title", "description": "Line one.\n\nLine two.\n", "version": int64(2)},
		"tags":    []any{"A", "B C", "d's"},
		"empty":   []any{},
		"obj":     map[string]any{},
		"list": []any{
			map[string]any{"name": "x", "in": "query", "schema": map[string]any{"type": "string"}},
			"plain",
			map[string]any{"nested": true},
		},
		"seqAtKeyIndent": []any{"one", "two"},
		"paths": map[string]any{"/v1/x": map[string]any{"get": map[string]any{
			"responses": map[string]any{"200": map[string]any{"description": "ok"}},
		}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %#v\nwant %#v", got, want)
	}
}

func TestParseYAMLSubsetRejects(t *testing.T) {
	for _, src := range []string{
		"a: 1\na: 2\n",
		"a: &x 1\n",
		"a: {b: 1}\n",
		"a: 1 # c\n",
		"a:\n\tb: 1\n",
		"a: [[1]]\n",
		"a:\n  b: 1\n   c: 2\n",
	} {
		if _, err := parseYAMLSubset(src); err == nil {
			t.Errorf("expected an error for %q", src)
		}
	}
}
