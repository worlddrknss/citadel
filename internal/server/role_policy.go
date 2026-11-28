package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Role permissions policies (2.7).
//
// A role's permissions policy limits what the temporary credentials minted
// for it (AssumeRole, AssumeRoleWithWebIdentity) may do. It is a small
// subset of an IAM identity policy:
//
//	{"Version": "2012-10-17", "Statement": [{
//	  "Effect": "Allow",
//	  "Action": ["secretsmanager:GetSecretValue", "secretsmanager:ListSecrets"],
//	  "Resource": "arn:aws:secretsmanager:*:*:secret:shop/prod/*"}]}
//
// Evaluation is deny by default: a request is allowed only when an Allow
// statement matches its action and resource and no Deny statement does.
// "*" and "?" are wildcards anywhere in Action and Resource; actions match
// case-insensitively. A role with no policy keeps the pre-2.7 behaviour:
// its sessions act with the whole account's access.
//
// Resources are checked for Secrets Manager (every per-secret action;
// ListSecrets and BatchGetSecretValue return only the secrets the policy
// allows them for). Every other action is checked against the resource
// "*", so it needs a statement whose Resource is "*": a statement scoped
// to secrets never grants, say, kms:CreateKey or ssm:GetParameter.

const maxRolePolicyBytes = 10240

// rolePolicy is a parsed, validated permissions policy.
type rolePolicy struct {
	statements []rolePolicyStatement
}

type rolePolicyStatement struct {
	allow     bool
	actions   []string
	resources []string
}

type rawRolePolicy struct {
	Version   string          `json:"Version"`
	Statement json.RawMessage `json:"Statement"`
}

// parseRolePolicy parses and validates a permissions policy document. It
// rejects what Citadel would otherwise silently ignore (Principal,
// NotAction, NotResource, Condition), so a policy never looks stricter
// than it is.
func parseRolePolicy(doc string) (*rolePolicy, error) {
	doc = strings.TrimSpace(doc)
	if doc == "" {
		return nil, errors.New("the policy is empty")
	}
	if len(doc) > maxRolePolicyBytes {
		return nil, fmt.Errorf("the policy is longer than %d bytes", maxRolePolicyBytes)
	}
	dec := json.NewDecoder(strings.NewReader(doc))
	dec.DisallowUnknownFields()
	var raw rawRolePolicy
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("the policy is not a valid policy document: %v", err)
	}
	if raw.Version != "" && raw.Version != "2012-10-17" {
		return nil, errors.New(`Version must be "2012-10-17"`)
	}
	var stmts []json.RawMessage
	switch t := strings.TrimSpace(string(raw.Statement)); {
	case t == "" || t == "null":
		return nil, errors.New("the policy has no Statement")
	case strings.HasPrefix(t, "["):
		if err := json.Unmarshal(raw.Statement, &stmts); err != nil {
			return nil, fmt.Errorf("Statement: %v", err)
		}
	default:
		stmts = []json.RawMessage{raw.Statement}
	}
	if len(stmts) == 0 {
		return nil, errors.New("the policy has no Statement")
	}
	p := &rolePolicy{}
	for i, rs := range stmts {
		st, err := parseRolePolicyStatement(rs)
		if err != nil {
			return nil, fmt.Errorf("Statement %d: %v", i+1, err)
		}
		p.statements = append(p.statements, st)
	}
	return p, nil
}

func parseRolePolicyStatement(raw json.RawMessage) (rolePolicyStatement, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return rolePolicyStatement{}, errors.New("must be an object")
	}
	for k := range fields {
		switch k {
		case "Sid", "Effect", "Action", "Resource":
		case "Principal", "NotPrincipal":
			return rolePolicyStatement{}, fmt.Errorf("%s is not allowed in a permissions policy (the role is the principal)", k)
		default:
			return rolePolicyStatement{}, fmt.Errorf("%s is not supported", k)
		}
	}
	var effect string
	if err := json.Unmarshal(fields["Effect"], &effect); err != nil || (effect != "Allow" && effect != "Deny") {
		return rolePolicyStatement{}, errors.New(`Effect must be "Allow" or "Deny"`)
	}
	actions, err := policyStrings(fields["Action"], "Action")
	if err != nil {
		return rolePolicyStatement{}, err
	}
	for _, a := range actions {
		if a != "*" && !strings.Contains(a, ":") {
			return rolePolicyStatement{}, fmt.Errorf("Action %q must be service:Action, for example secretsmanager:GetSecretValue", a)
		}
	}
	resources, err := policyStrings(fields["Resource"], "Resource")
	if err != nil {
		return rolePolicyStatement{}, err
	}
	return rolePolicyStatement{allow: effect == "Allow", actions: actions, resources: resources}, nil
}

// policyStrings decodes a string or a non-empty array of strings.
func policyStrings(raw json.RawMessage, name string) ([]string, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%s is required", name)
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		if strings.TrimSpace(one) == "" {
			return nil, fmt.Errorf("%s must not be empty", name)
		}
		return []string{strings.TrimSpace(one)}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil || len(many) == 0 {
		return nil, fmt.Errorf("%s must be a string or a list of strings", name)
	}
	out := make([]string, 0, len(many))
	for _, v := range many {
		if strings.TrimSpace(v) == "" {
			return nil, fmt.Errorf("%s must not contain an empty value", name)
		}
		out = append(out, strings.TrimSpace(v))
	}
	return out, nil
}

// allows reports whether the policy allows action on resource: some Allow
// statement matches and no Deny statement does.
func (p *rolePolicy) allows(action, resource string) bool {
	if p == nil {
		return false
	}
	allowed := false
	for _, st := range p.statements {
		if !st.matchesAction(action) || !globAny(st.resources, resource, false) {
			continue
		}
		if !st.allow {
			return false
		}
		allowed = true
	}
	return allowed
}

// allowsActionOnAny reports whether some resource could be allowed for
// action: an Allow statement matches the action. It gates actions whose
// resources the handler checks itself; a Deny on "*" still refuses.
func (p *rolePolicy) allowsActionOnAny(action string) bool {
	if p == nil {
		return false
	}
	allowed := false
	for _, st := range p.statements {
		if !st.matchesAction(action) {
			continue
		}
		if !st.allow {
			if slicesContains(st.resources, "*") {
				return false
			}
			continue
		}
		allowed = true
	}
	return allowed
}

func (st rolePolicyStatement) matchesAction(action string) bool {
	return globAny(st.actions, action, true)
}

func slicesContains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func globAny(patterns []string, target string, caseInsensitive bool) bool {
	for _, p := range patterns {
		if caseInsensitive {
			if globMatch(strings.ToLower(p), strings.ToLower(target)) {
				return true
			}
		} else if globMatch(p, target) {
			return true
		}
	}
	return false
}

// globMatch matches target against pattern, where "*" matches any run of
// characters (including none) and "?" any single character.
func globMatch(pattern, target string) bool {
	p, t := 0, 0
	star, mark := -1, 0
	for t < len(target) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == target[t]):
			p++
			t++
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, t
			p++
		case star >= 0:
			p = star + 1
			mark++
			t = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// iamActionForTarget maps an AWS JSON-protocol X-Amz-Target to its IAM
// action, for example "secretsmanager.GetSecretValue" to
// "secretsmanager:GetSecretValue". It returns "" for an unknown service.
func iamActionForTarget(target string) string {
	svc := awsServiceFromTarget(target)
	_, op, ok := strings.Cut(target, ".")
	if svc == "" || !ok || op == "" {
		return ""
	}
	return svc + ":" + op
}

// roleResourceCheckedActions are the actions whose handlers check the
// role policy against the resource they act on (or filter what they
// return by it). Every other action is checked against resource "*".
var roleResourceCheckedActions = map[string]bool{
	"secretsmanager:CreateSecret":             true,
	"secretsmanager:DescribeSecret":           true,
	"secretsmanager:GetSecretValue":           true,
	"secretsmanager:PutSecretValue":           true,
	"secretsmanager:UpdateSecret":             true,
	"secretsmanager:DeleteSecret":             true,
	"secretsmanager:RestoreSecret":            true,
	"secretsmanager:ListSecrets":              true,
	"secretsmanager:ListSecretVersionIds":     true,
	"secretsmanager:TagResource":              true,
	"secretsmanager:UntagResource":            true,
	"secretsmanager:GetResourcePolicy":        true,
	"secretsmanager:PutResourcePolicy":        true,
	"secretsmanager:DeleteResourcePolicy":     true,
	"secretsmanager:RotateSecret":             true,
	"secretsmanager:CancelRotateSecret":       true,
	"secretsmanager:UpdateSecretVersionStage": true,
	"secretsmanager:BatchGetSecretValue":      true,
}

// roleActionAllowed is the gate every AWS JSON-protocol request from a
// restricted role session passes before its handler runs.
func roleActionAllowed(p *rolePolicy, action string) bool {
	if action == "" {
		return false
	}
	if roleResourceCheckedActions[action] {
		return p.allowsActionOnAny(action)
	}
	return p.allows(action, "*")
}
