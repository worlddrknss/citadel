package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/worlddrknss/citadel/internal/store"
)

func (s *Server) authorizeKeyAction(ctx context.Context, r *http.Request, key store.KMSKey, action string) error {
	policy, err := s.store.GetKeyPolicy(ctx, key.ID, "default")
	if err != nil {
		return err
	}
	principal := requestPrincipal(r)
	decision, err := policyDecision(policy, principal, action, key.ARN, s.cfg.DefaultDenyPolicy)
	if err != nil {
		return err
	}
	switch decision {
	case policyAllow:
		return nil
	case policyExplicitDeny:
		// An explicit Deny in the key policy overrides any grant, as in AWS.
		return errAccessDenied
	}
	// Implicitly denied by the key policy: a grant to this principal for this
	// operation authorizes it.
	if s.grantAllows(ctx, key.ID, principal, action) {
		return nil
	}
	return errAccessDenied
}

func requestPrincipal(r *http.Request) string {
	if c, ok := awsCallerFromContext(r.Context()); ok {
		return c.PrincipalARN()
	}
	auth := r.Header.Get("Authorization")
	if idx := strings.Index(auth, "Credential="); idx >= 0 {
		rest := auth[idx+len("Credential="):]
		if slash := strings.Index(rest, "/"); slash > 0 {
			accessKey := strings.TrimSpace(rest[:slash])
			if accessKey != "" {
				return "arn:aws:iam::000000000000:user/" + accessKey
			}
		}
	}
	return "arn:aws:iam::000000000000:root"
}

// policyAllows evaluates an AWS-style policy document. An explicit Deny always
// wins. When no statement matches the action/resource, the result depends on
// defaultDeny: false preserves the permissive legacy behavior, true enforces
// AWS-like deny-by-default.
func policyAllows(rawPolicy, principal, action, resource string, defaultDeny bool) (bool, error) {
	d, err := policyDecision(rawPolicy, principal, action, resource, defaultDeny)
	return d == policyAllow, err
}

type policyResult int

const (
	policyImplicitDeny policyResult = iota
	policyAllow
	policyExplicitDeny
)

// policyDecision evaluates a policy like policyAllows but distinguishes an
// explicit Deny from an implicit one, which grants can still override.
func policyDecision(rawPolicy, principal, action, resource string, defaultDeny bool) (policyResult, error) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(rawPolicy), &doc); err != nil {
		return policyImplicitDeny, err
	}
	statements := asPolicyStatements(doc["Statement"])
	hasRelevantStatement := false
	allowed := false
	for _, stmt := range statements {
		if valueMatches(stmt["Action"], action, true) && valueMatches(stmt["Resource"], resource, false) {
			hasRelevantStatement = true
		}
		if !policyStatementMatches(stmt, principal, action, resource) {
			continue
		}
		effect := strings.ToLower(strings.TrimSpace(stringValue(stmt["Effect"])))
		if effect == "deny" {
			return policyExplicitDeny, nil
		}
		if effect == "allow" {
			allowed = true
		}
	}
	if allowed || (!hasRelevantStatement && !defaultDeny) {
		return policyAllow, nil
	}
	return policyImplicitDeny, nil
}

// grantOperations are the operations a KMS grant may allow (AWS's list).
var grantOperations = map[string]bool{
	"Decrypt": true, "Encrypt": true, "GenerateDataKey": true, "GenerateDataKeyWithoutPlaintext": true,
	"ReEncryptFrom": true, "ReEncryptTo": true, "Sign": true, "Verify": true, "GetPublicKey": true,
	"CreateGrant": true, "RetireGrant": true, "DescribeKey": true, "GenerateDataKeyPair": true,
	"GenerateDataKeyPairWithoutPlaintext": true, "GenerateMac": true, "VerifyMac": true, "DeriveSharedSecret": true,
}

// grantAllows reports whether a grant on the key lets principal perform the
// kms:<Operation> action. Grants are read within the caller's account.
func (s *Server) grantAllows(ctx context.Context, keyID, principal, action string) bool {
	op, ok := strings.CutPrefix(action, "kms:")
	if !ok || !grantOperations[op] {
		return false
	}
	grants, err := s.store.ListGrants(ctx, keyID)
	if err != nil {
		return false
	}
	for _, g := range grants {
		if g.GranteePrincipal != principal {
			continue
		}
		for _, o := range g.Operations {
			if o == op {
				return true
			}
		}
	}
	return false
}

func asPolicyStatements(value any) []map[string]any {
	switch typed := value.(type) {
	case []any:
		out := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			if stmt, ok := item.(map[string]any); ok {
				out = append(out, stmt)
			}
		}
		return out
	case map[string]any:
		return []map[string]any{typed}
	default:
		return nil
	}
}

func policyStatementMatches(stmt map[string]any, principal, action, resource string) bool {
	return principalMatches(stmt["Principal"], principal) && valueMatches(stmt["Action"], action, true) && valueMatches(stmt["Resource"], resource, false)
}

func principalMatches(value any, principal string) bool {
	if value == nil {
		return false
	}
	if stringValue(value) == "*" {
		return true
	}
	if principalMap, ok := value.(map[string]any); ok {
		return valueMatches(principalMap["AWS"], principal, false)
	}
	return valueMatches(value, principal, false)
}

func valueMatches(value any, target string, caseInsensitive bool) bool {
	patterns := stringValues(value)
	for _, pattern := range patterns {
		if wildcardMatch(pattern, target, caseInsensitive) {
			return true
		}
	}
	return false
}

func stringValues(value any) []string {
	switch typed := value.(type) {
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return []string{typed}
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if s := stringValue(item); strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		if s := stringValue(value); strings.TrimSpace(s) != "" {
			return []string{s}
		}
		return nil
	}
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return fmt.Sprint(value)
	}
}

func wildcardMatch(pattern, target string, caseInsensitive bool) bool {
	if caseInsensitive {
		pattern = strings.ToLower(pattern)
		target = strings.ToLower(target)
	}
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(target, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == target
}

func normalizePolicyDocument(raw string) (string, error) {
	var doc any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
