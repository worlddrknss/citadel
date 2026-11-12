package main

import (
	"crypto/rand"
	"testing"
)

func TestWrapUnwrapKeyMaterialRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	s := &dbStore{wrappingKey: key}
	wrapped, nonce, err := s.wrapKeyMaterial("key-1", []byte("material"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.unwrapKeyMaterial("key-1", wrapped, nonce)
	if err != nil || string(got) != "material" {
		t.Fatalf("unwrap = %q, %v", got, err)
	}
	if _, err := s.unwrapKeyMaterial("key-2", wrapped, nonce); err == nil {
		t.Fatal("unwrap with another key ID must fail")
	}
}
