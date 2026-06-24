package main

import (
	"context"
	"testing"
)

func newParamTestServer() *server {
	store := &inMemoryStore{k: sampleKey(1)}
	return &server{cfg: config{}, store: store}
}

func TestNormalizeParameterName(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"/app/prod/db", "/app/prod/db", true},
		{"app/prod/db", "/app/prod/db", true},
		{"/app/prod/db/", "/app/prod/db", true},
		{"db.password", "/db.password", true},
		{"", "", false},
		{"/app/bad seg", "", false},
	}
	for _, c := range cases {
		got, err := normalizeParameterName(c.in)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("normalizeParameterName(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("normalizeParameterName(%q) expected error", c.in)
		}
	}
}

func TestParameterStoreRoundtrip(t *testing.T) {
	s := newParamTestServer()
	ps, ok := s.paramStore()
	if !ok {
		t.Fatal("in-memory store does not implement parameterStore")
	}
	ctx := context.Background()

	// String parameter.
	rec, err := s.buildParameterRecord(ctx, "/app/prod/name", "String", "citadel", "", "", "service name")
	if err != nil {
		t.Fatalf("build String: %v", err)
	}
	saved, err := ps.PutParameter(ctx, rec, false)
	if err != nil {
		t.Fatalf("put String: %v", err)
	}
	if saved.Version != 1 {
		t.Fatalf("expected version 1, got %d", saved.Version)
	}

	// Creating again without overwrite should conflict.
	if _, err := ps.PutParameter(ctx, rec, false); err != errParameterExists {
		t.Fatalf("expected errParameterExists, got %v", err)
	}

	// Overwrite bumps the version.
	saved2, err := ps.PutParameter(ctx, rec, true)
	if err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	if saved2.Version != 2 {
		t.Fatalf("expected version 2, got %d", saved2.Version)
	}

	// SecureString round-trips through KMS encryption.
	secRec, err := s.buildParameterRecord(ctx, "/app/prod/secret", "SecureString", "s3cr3t", "", "", "")
	if err != nil {
		t.Fatalf("build SecureString: %v", err)
	}
	if !secRec.IsEncrypted || secRec.Value == "s3cr3t" {
		t.Fatalf("SecureString value was not encrypted: %+v", secRec)
	}
	if _, err := ps.PutParameter(ctx, secRec, false); err != nil {
		t.Fatalf("put SecureString: %v", err)
	}
	stored, err := ps.GetParameter(ctx, "/app/prod/secret")
	if err != nil {
		t.Fatalf("get SecureString: %v", err)
	}
	plain, err := s.decryptParameterValue(ctx, stored.KMSKeyID, stored.Value)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if plain != "s3cr3t" {
		t.Fatalf("decrypted value = %q, want s3cr3t", plain)
	}

	// History captures every version.
	history, err := ps.GetParameterHistory(ctx, "/app/prod/name")
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("expected 2 history entries, got %d", len(history))
	}

	// Labels move between versions.
	labels, err := ps.LabelParameterVersion(ctx, "/app/prod/name", 1, []string{"stable"})
	if err != nil {
		t.Fatalf("label v1: %v", err)
	}
	if len(labels) != 1 || labels[0] != "stable" {
		t.Fatalf("unexpected labels: %v", labels)
	}
	if _, err := ps.LabelParameterVersion(ctx, "/app/prod/name", 2, []string{"stable"}); err != nil {
		t.Fatalf("label v2: %v", err)
	}
	history, _ = ps.GetParameterHistory(ctx, "/app/prod/name")
	for _, h := range history {
		if h.Version == 1 && len(h.Labels) != 0 {
			t.Fatalf("label should have moved off version 1: %v", h.Labels)
		}
		if h.Version == 2 && (len(h.Labels) != 1 || h.Labels[0] != "stable") {
			t.Fatalf("version 2 should hold the label: %v", h.Labels)
		}
	}

	// Tags.
	if err := ps.TagParameter(ctx, "/app/prod/name", []paramTag{{Key: "team", Value: "platform"}}); err != nil {
		t.Fatalf("tag: %v", err)
	}
	tags, err := ps.ListParameterTags(ctx, "/app/prod/name")
	if err != nil || len(tags) != 1 || tags[0].Key != "team" {
		t.Fatalf("list tags: %v %v", tags, err)
	}

	// Delete removes the parameter.
	if err := ps.DeleteParameter(ctx, "/app/prod/name"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := ps.GetParameter(ctx, "/app/prod/name"); err != errParameterNotFound {
		t.Fatalf("expected errParameterNotFound, got %v", err)
	}
}
