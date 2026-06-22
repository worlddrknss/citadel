package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestACMEChallengeStoreRoundTrip(t *testing.T) {
	store := newACMEChallengeStore()
	if _, ok := store.get("missing"); ok {
		t.Fatalf("expected missing token to be absent")
	}
	store.set("tok123", "keyauth-value")
	got, ok := store.get("tok123")
	if !ok || got != "keyauth-value" {
		t.Fatalf("got (%q, %v), want (keyauth-value, true)", got, ok)
	}
	store.delete("tok123")
	if _, ok := store.get("tok123"); ok {
		t.Fatalf("expected token to be deleted")
	}
}

func TestHandleACMEChallengeToken(t *testing.T) {
	s := &server{acmeChallenges: newACMEChallengeStore()}
	s.acmeChallenges.set("validtoken", "the-key-authorization")

	t.Run("serves stored key authorization", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/validtoken", nil)
		req.SetPathValue("token", "validtoken")
		rec := httptest.NewRecorder()
		s.handleACMEChallengeToken(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if rec.Body.String() != "the-key-authorization" {
			t.Fatalf("body = %q, want the-key-authorization", rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); ct != "text/plain" {
			t.Fatalf("content-type = %q, want text/plain", ct)
		}
	})

	t.Run("unknown token is 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/nope", nil)
		req.SetPathValue("token", "nope")
		rec := httptest.NewRecorder()
		s.handleACMEChallengeToken(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestNormalizeDomains(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"comma separated", []string{"example.com,www.example.com"}, []string{"example.com", "www.example.com"}},
		{"mixed separators and case", []string{"Example.com www.EXAMPLE.com\napi.example.com"}, []string{"example.com", "www.example.com", "api.example.com"}},
		{"dedupes", []string{"a.com, a.com,b.com"}, []string{"a.com", "b.com"}},
		{"empty", []string{"  ", ""}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeDomains(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("normalizeDomains(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestLEDirectoryEnvLabel(t *testing.T) {
	cases := map[string]string{
		leProdDirectoryURL:             "production",
		leStagingDirectoryURL:          "staging",
		"":                             "staging",
		"https://example.com/acme/dir": "custom",
	}
	for url, want := range cases {
		if got := leDirectoryEnvLabel(url); got != want {
			t.Fatalf("leDirectoryEnvLabel(%q) = %q, want %q", url, got, want)
		}
	}
}

func TestACMELEStoreUnsupportedInMemory(t *testing.T) {
	var store keyStore = &inMemoryStore{}
	ctx := context.Background()
	if _, err := store.GetACMELEAccount(ctx, leStagingDirectoryURL); err != errUnsupported {
		t.Fatalf("GetACMELEAccount err = %v, want errUnsupported", err)
	}
	if err := store.UpsertACMELEAccount(ctx, acmeLEAccount{}); err != errUnsupported {
		t.Fatalf("UpsertACMELEAccount err = %v, want errUnsupported", err)
	}
	if err := store.CreateACMELECertificate(ctx, acmeLECertificate{}); err != errUnsupported {
		t.Fatalf("CreateACMELECertificate err = %v, want errUnsupported", err)
	}
	if _, err := store.ListACMELECertificates(ctx); err != errUnsupported {
		t.Fatalf("ListACMELECertificates err = %v, want errUnsupported", err)
	}
}
