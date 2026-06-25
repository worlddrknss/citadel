package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestTrustPolicySubjectAllowed(t *testing.T) {
	p := trustPolicy{Subjects: []string{"system:serviceaccount:app:secrets", "system:serviceaccount:ci:*"}}
	cases := []struct {
		sub  string
		want bool
	}{
		{"system:serviceaccount:app:secrets", true},
		{"system:serviceaccount:ci:runner", true},
		{"system:serviceaccount:ci:", true},
		{"system:serviceaccount:other:sa", false},
		{"", false},
	}
	for _, c := range cases {
		if got := p.subjectAllowed(c.sub); got != c.want {
			t.Errorf("subjectAllowed(%q) = %v, want %v", c.sub, got, c.want)
		}
	}

	wild := trustPolicy{Subjects: []string{"*"}}
	if !wild.subjectAllowed("anything") {
		t.Error("wildcard subject should allow any non-empty subject")
	}
	if wild.subjectAllowed("") {
		t.Error("wildcard subject must still reject empty subject")
	}
}

func TestTrustPolicyAudienceAllowed(t *testing.T) {
	p := trustPolicy{Audiences: []string{"sts.citadel.local", "other"}}
	if !p.audienceAllowed([]string{"unrelated", "sts.citadel.local"}) {
		t.Error("expected audience match")
	}
	if p.audienceAllowed([]string{"nope"}) {
		t.Error("did not expect audience match")
	}
	empty := trustPolicy{}
	if empty.audienceAllowed([]string{"sts.citadel.local"}) {
		t.Error("policy with no audiences must reject all")
	}
}

func TestTrustPolicyPrincipalAllowed(t *testing.T) {
	p := trustPolicy{Principals: []string{"123456789012"}}
	if !p.principalAllowed("123456789012") {
		t.Error("expected principal match")
	}
	if p.principalAllowed("999999999999") {
		t.Error("did not expect principal match")
	}
	wild := trustPolicy{Principals: []string{"*"}}
	if !wild.principalAllowed("123456789012") {
		t.Error("wildcard principal should allow any account")
	}
}

func TestTempAccessKeyID(t *testing.T) {
	id := generateTempAccessKeyID()
	if !strings.HasPrefix(id, "ASIA") {
		t.Errorf("temp key ID %q must start with ASIA", id)
	}
	if !isTempAccessKeyID(id) {
		t.Errorf("isTempAccessKeyID(%q) = false, want true", id)
	}
	if isTempAccessKeyID("AKIAEXAMPLE") {
		t.Error("long-lived AKIA key must not be classified as temporary")
	}
	if a, b := generateTempAccessKeyID(), generateTempAccessKeyID(); a == b {
		t.Error("temp key IDs should be unique")
	}
}

func TestClampDuration(t *testing.T) {
	cases := []struct {
		raw     string
		maxSecs int
		want    time.Duration
	}{
		{"", 3600, 3600 * time.Second},
		{"7200", 3600, 3600 * time.Second}, // clamped to max
		{"100", 3600, 900 * time.Second},   // clamped to floor
		{"1800", 3600, 1800 * time.Second},
		{"bad", 3600, 3600 * time.Second},
		{"1800", 0, 1800 * time.Second}, // max defaults to 3600
	}
	for _, c := range cases {
		if got := clampDuration(c.raw, c.maxSecs); got != c.want {
			t.Errorf("clampDuration(%q, %d) = %v, want %v", c.raw, c.maxSecs, got, c.want)
		}
	}
}

func TestDecodeAudience(t *testing.T) {
	single, _ := json.Marshal("sts.citadel.local")
	if got := decodeAudience(single); len(got) != 1 || got[0] != "sts.citadel.local" {
		t.Errorf("single audience decode = %v", got)
	}
	many, _ := json.Marshal([]string{"a", "b"})
	if got := decodeAudience(many); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("array audience decode = %v", got)
	}
	if got := decodeAudience(nil); got != nil {
		t.Errorf("empty audience should decode to nil, got %v", got)
	}
}

func TestIssuerHost(t *testing.T) {
	cases := map[string]string{
		"https://oidc.example.com":         "oidc.example.com",
		"https://oidc.example.com/":        "oidc.example.com",
		"https://example.com/cluster/abc":  "example.com/cluster/abc",
		"https://example.com/cluster/abc/": "example.com/cluster/abc",
	}
	for in, want := range cases {
		got, err := issuerHost(in)
		if err != nil {
			t.Errorf("issuerHost(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("issuerHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeIssuerURL(t *testing.T) {
	if got := normalizeIssuerURL("https://x/ "); got != "https://x" {
		t.Errorf("normalizeIssuerURL trailing slash/space = %q", got)
	}
}
