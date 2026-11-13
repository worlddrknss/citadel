package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/worlddrknss/citadel/docs"
	"github.com/worlddrknss/citadel/internal/config"
	"github.com/worlddrknss/citadel/internal/store/memory"
)

// The tests in this file keep docs/openapi.yaml honest: every /v1 route the
// server registers must be documented and every documented route must exist;
// each operation's x-citadel-role must match the role the handler asks for,
// and its x-citadel-audit must name the actions the handler records; and the
// TypeScript SDK's generated types must have been generated from this exact
// document.

var httpMethods = map[string]bool{"get": true, "post": true, "put": true, "patch": true, "delete": true, "head": true, "options": true}

// registeredRoute is one mux registration found in the package source.
type registeredRoute struct {
	key     string // "GET /v1/me"
	handler string // method name on *Server, when registered as s.handleX
	pos     string
}

// sourceIndex is the parsed (non-test) source of this package.
type sourceIndex struct {
	routes   []registeredRoute
	funcs    map[string]*ast.FuncDecl // methods on *Server by name
	literals map[string]bool          // every string literal
}

func indexSource(t *testing.T) *sourceIndex {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	idx := &sourceIndex{funcs: map[string]*ast.FuncDecl{}, literals: map[string]bool{}}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv != nil {
				idx.funcs[fd.Name.Name] = fd
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.BasicLit:
				if n.Kind == token.STRING {
					if v, err := strconv.Unquote(n.Value); err == nil {
						idx.literals[v] = true
					}
				}
			case *ast.CallExpr:
				sel, ok := n.Fun.(*ast.SelectorExpr)
				if !ok || (sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle") || len(n.Args) != 2 {
					return true
				}
				lit, ok := n.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				pattern, _ := strconv.Unquote(lit.Value)
				method, path, hasMethod := strings.Cut(pattern, " ")
				if !hasMethod {
					path = pattern
				}
				if !strings.HasPrefix(path, "/v1/") {
					return true
				}
				pos := fset.Position(lit.Pos()).String()
				if !hasMethod {
					t.Errorf("%s: /v1 route %q has no method; register it as \"METHOD /v1/...\"", pos, pattern)
					return true
				}
				r := registeredRoute{key: method + " " + path, pos: pos}
				if hs, ok := n.Args[1].(*ast.SelectorExpr); ok {
					if id, ok := hs.X.(*ast.Ident); ok && id.Name == "s" {
						r.handler = hs.Sel.Name
					}
				}
				idx.routes = append(idx.routes, r)
			}
			return true
		})
	}
	return idx
}

// recordsAction reports whether action appears in the source as a string
// literal, or is built from a literal prefix ending in ":" (such as
// "citadel.Bulk:" + op).
func (idx *sourceIndex) recordsAction(action string) bool {
	if idx.literals[action] {
		return true
	}
	if i := strings.LastIndex(action, ":"); i > 0 {
		return idx.literals[action[:i+1]]
	}
	return false
}

type specOperation struct {
	key string
	op  map[string]any
}

func loadSpec(t *testing.T) (map[string]any, []specOperation) {
	t.Helper()
	raw, err := parseYAMLSubset(string(docs.OpenAPI))
	if err != nil {
		t.Fatalf("docs/openapi.yaml is not in the supported YAML subset: %v", err)
	}
	doc, ok := raw.(map[string]any)
	if !ok {
		t.Fatal("docs/openapi.yaml: top level is not a mapping")
	}
	if doc["openapi"] != "3.1.0" {
		t.Fatalf("openapi version = %v, want 3.1.0", doc["openapi"])
	}
	paths, _ := doc["paths"].(map[string]any)
	var ops []specOperation
	for path, item := range paths {
		methods, _ := item.(map[string]any)
		for m, op := range methods {
			if !httpMethods[m] {
				t.Errorf("%s: unexpected key %q in path item", path, m)
				continue
			}
			om, _ := op.(map[string]any)
			ops = append(ops, specOperation{key: strings.ToUpper(m) + " " + path, op: om})
		}
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].key < ops[j].key })
	return doc, ops
}

// TestOpenAPICoversRegisteredRoutes fails when a registered /v1 route is
// missing from docs/openapi.yaml, or the document lists a route that does
// not exist.
func TestOpenAPICoversRegisteredRoutes(t *testing.T) {
	idx := indexSource(t)
	_, ops := loadSpec(t)
	registered := map[string]registeredRoute{}
	for _, r := range idx.routes {
		if prev, dup := registered[r.key]; dup {
			t.Errorf("%s: route %s registered twice (also %s)", r.pos, r.key, prev.pos)
		}
		registered[r.key] = r
	}
	documented := map[string]bool{}
	for _, o := range ops {
		documented[o.key] = true
		if _, ok := registered[o.key]; !ok {
			t.Errorf("docs/openapi.yaml documents %s, which the server does not register", o.key)
		}
	}
	for key, r := range registered {
		if !documented[key] {
			t.Errorf("%s: route %s is not documented in docs/openapi.yaml", r.pos, key)
		}
	}
	if len(registered) < 150 {
		t.Errorf("found only %d /v1 routes; the source scan is probably broken", len(registered))
	}
}

// TestOpenAPIOperationsWellFormed checks each operation's metadata and that
// every $ref resolves.
func TestOpenAPIOperationsWellFormed(t *testing.T) {
	doc, ops := loadSpec(t)
	declaredTags := map[string]bool{}
	tags, _ := doc["tags"].([]any)
	for _, tg := range tags {
		if m, ok := tg.(map[string]any); ok {
			declaredTags[m["name"].(string)] = true
		}
	}
	roles := map[string]bool{"public": true, "session": true, "viewer": true, "editor": true, "admin": true, "platform-admin": true}
	ids := map[string]string{}
	for _, o := range ops {
		id, _ := o.op["operationId"].(string)
		if id == "" {
			t.Errorf("%s: no operationId", o.key)
		} else if prev, dup := ids[id]; dup {
			t.Errorf("%s: operationId %q also used by %s", o.key, id, prev)
		}
		ids[id] = o.key
		if s, _ := o.op["summary"].(string); s == "" {
			t.Errorf("%s: no summary", o.key)
		}
		opTags, _ := o.op["tags"].([]any)
		if len(opTags) == 0 {
			t.Errorf("%s: no tags", o.key)
		}
		for _, tg := range opTags {
			if s, _ := tg.(string); !declaredTags[s] {
				t.Errorf("%s: tag %v is not declared in the top-level tags", o.key, tg)
			}
		}
		role, _ := o.op["x-citadel-role"].(string)
		if !roles[role] {
			t.Errorf("%s: x-citadel-role %q is not one of public, session, viewer, editor, admin, platform-admin", o.key, role)
		}
		// Public operations, and only they, allow anonymous callers: security
		// is [] or includes the empty requirement {}.
		anonymous := false
		if sec, ok := o.op["security"].([]any); ok {
			anonymous = len(sec) == 0
			for _, req := range sec {
				if m, ok := req.(map[string]any); ok && len(m) == 0 {
					anonymous = true
				}
			}
		}
		if (role == "public") != anonymous {
			t.Errorf("%s: public operations (and only they) must allow anonymous callers (security: [] or a {} requirement)", o.key)
		}
		if resp, _ := o.op["responses"].(map[string]any); len(resp) == 0 {
			t.Errorf("%s: no responses", o.key)
		}
	}
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch v := v.(type) {
		case map[string]any:
			for k, c := range v {
				if k == "$ref" {
					ref, _ := c.(string)
					if resolveRef(doc, ref) == nil {
						t.Errorf("%s: $ref %q does not resolve", path, ref)
					}
					continue
				}
				walk(path+"/"+k, c)
			}
		case []any:
			for i, c := range v {
				walk(path+"/"+strconv.Itoa(i), c)
			}
		}
	}
	walk("#", doc)
}

func resolveRef(doc map[string]any, ref string) any {
	if !strings.HasPrefix(ref, "#/") {
		return nil
	}
	var cur any = doc
	for _, part := range strings.Split(ref[2:], "/") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		if cur, ok = m[part]; !ok {
			return nil
		}
	}
	return cur
}

// handlerFacts is what a handler's own body says about its role and audit.
type handlerFacts struct {
	role   string          // "" when the handler doesn't call a session helper directly
	audits map[string]bool // Action literals recorded with Result "ok"
}

func factsFor(fd *ast.FuncDecl) handlerFacts {
	f := handlerFacts{audits: map[string]bool{}}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			sel, ok := n.Fun.(*ast.SelectorExpr)
			if !ok || f.role != "" {
				return true
			}
			switch sel.Sel.Name {
			case "requirePlatformAdmin":
				f.role = "platform-admin"
			case "nativeSession", "secretsSession", "resolveNativeSession":
				if len(n.Args) == 3 {
					if lit, ok := n.Args[2].(*ast.BasicLit); ok {
						f.role, _ = strconv.Unquote(lit.Value)
					}
				}
			}
		case *ast.CompositeLit:
			var action, result string
			for _, el := range n.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				k, _ := kv.Key.(*ast.Ident)
				lit, _ := kv.Value.(*ast.BasicLit)
				if k == nil || lit == nil {
					continue
				}
				v, _ := strconv.Unquote(lit.Value)
				switch k.Name {
				case "Action":
					action = v
				case "Result":
					result = v
				}
			}
			if action != "" && result == "ok" {
				f.audits[action] = true
			}
		}
		return true
	})
	return f
}

func specAudits(op map[string]any) []string {
	switch v := op["x-citadel-audit"].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, a := range v {
			s, _ := a.(string)
			out = append(out, s)
		}
		return out
	}
	return nil
}

// TestOpenAPIRolesAndAuditMatchHandlers compares x-citadel-role and
// x-citadel-audit with what each handler does, where the handler does it
// directly (helpers that wrap the session or audit calls are not traced).
func TestOpenAPIRolesAndAuditMatchHandlers(t *testing.T) {
	idx := indexSource(t)
	_, ops := loadSpec(t)
	handlers := map[string]string{}
	for _, r := range idx.routes {
		handlers[r.key] = r.handler
	}
	for _, o := range ops {
		audits := specAudits(o.op)
		for _, a := range audits {
			if !idx.recordsAction(a) {
				t.Errorf("%s: x-citadel-audit %q is not an action the server records", o.key, a)
			}
		}
		fd := idx.funcs[handlers[o.key]]
		if fd == nil {
			continue
		}
		facts := factsFor(fd)
		if facts.role != "" {
			role, _ := o.op["x-citadel-role"].(string)
			// "session" is any signed-in caller (the viewer floor), and a
			// handler that asks for admin may narrow to platform admins
			// with its own check.
			compatible := role == facts.role ||
				(role == "session" && facts.role == "viewer") ||
				(role == "platform-admin" && facts.role == "admin")
			if !compatible {
				t.Errorf("%s: x-citadel-role is %q but %s requires %q", o.key, role, fd.Name.Name, facts.role)
			}
		}
		listed := map[string]bool{}
		for _, a := range audits {
			listed[a] = true
		}
		for a := range facts.audits {
			if !listed[a] {
				t.Errorf("%s: %s records %q, which x-citadel-audit does not list", o.key, fd.Name.Name, a)
			}
		}
	}
}

// TestOpenAPITypeScriptTypesCurrent fails when the TypeScript SDK's
// generated types were not regenerated after docs/openapi.yaml changed
// (run `npm run generate` in sdk/typescript).
func TestOpenAPITypeScriptTypesCurrent(t *testing.T) {
	const generated = "../../sdk/typescript/src/generated/openapi.ts"
	f, err := os.Open(generated)
	if err != nil {
		t.Fatalf("open %s: %v", generated, err)
	}
	defer f.Close()
	first, err := bufio.NewReader(f).ReadString('\n')
	if err != nil {
		t.Fatalf("read %s: %v", generated, err)
	}
	sum := sha256.Sum256(docs.OpenAPI)
	want := "// spec-sha256: " + hex.EncodeToString(sum[:])
	if strings.TrimSpace(first) != want {
		t.Fatalf("%s is stale: its first line is %q, want %q; run `npm run generate` in sdk/typescript", generated, strings.TrimSpace(first), want)
	}
}

// TestOpenAPIServed checks GET /v1/openapi.yaml: public, also in bootstrap
// mode, and byte-for-byte the embedded document.
func TestOpenAPIServed(t *testing.T) {
	st := &memory.Store{DefaultKey: sampleKey(1)}
	s := &Server{cfg: config.Config{}, store: st}
	s.authV = newAuthState()
	h := s.Handler()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/openapi.yaml", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/yaml") {
		t.Errorf("Content-Type = %q", ct)
	}
	if !bytes.Equal(rec.Body.Bytes(), docs.OpenAPI) {
		t.Error("served document differs from docs/openapi.yaml")
	}
}
