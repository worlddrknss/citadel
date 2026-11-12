package store

import (
	"bytes"
	"testing"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
)

func TestParseCipherBlobFormats(t *testing.T) {
	material := bytes.Repeat([]byte{9}, 32)
	v1, err := cryptoutil.EncryptBlob(material, "key-1", []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	p := cryptoutil.ParseCipherBlob(v1)
	if !p.Header || p.Version != 1 || p.KeyID != "key-1" || p.MaterialID != "" {
		t.Fatalf("v1 parse: %+v", p)
	}
	v2, err := cryptoutil.EncryptBlobWithMaterial(material, "key-1", "mat-7", []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	p = cryptoutil.ParseCipherBlob(v2)
	if !p.Header || p.Version != 2 || p.KeyID != "key-1" || p.MaterialID != "mat-7" {
		t.Fatalf("v2 parse: %+v", p)
	}
	if out, err := cryptoutil.GCMOpen(material, p.Sealed, nil); err != nil || string(out) != "x" {
		t.Fatalf("open v2 sealed part: %q %v", out, err)
	}
	// An empty material ID keeps the v1 format.
	same, _ := cryptoutil.EncryptBlobWithMaterial(material, "key-1", "", []byte("x"), nil)
	if same[0] != cryptoutil.CipherBlobVersionV1 {
		t.Fatalf("empty material ID should write v1, got version byte %d", same[0])
	}
	// Truncated input is reported as headerless rather than panicking.
	for _, b := range [][]byte{{2}, {2, 5, 'a'}, {2, 1, 'k', 9}, {1, 200}} {
		if p := cryptoutil.ParseCipherBlob(b); p.Header {
			t.Fatalf("malformed %v parsed as header: %+v", b, p)
		}
	}
}

func TestKeyDecryptsEveryMaterialVersionAndLegacyBlobs(t *testing.T) {
	orig := bytes.Repeat([]byte{1}, 32)
	key := KMSKey{ID: "k1", MasterKeyRaw: orig, KeyUsage: KeyUsageEncryptDecrypt, KeySpec: KeySpecSymmetricDefault}
	aad := cryptoutil.CanonicalContext(map[string]string{"a": "b"})

	// Blobs written before versioned material existed.
	legacy, _ := cryptoutil.EncryptLegacyBlob(orig, []byte("legacy"), aad)
	v1, _ := cryptoutil.EncryptBlob(orig, "k1", []byte("v1"), aad)
	// Same key, before any rotation: still writes v1.
	pre, err := key.EncryptBlob([]byte("pre"), aad)
	if err != nil || pre[0] != cryptoutil.CipherBlobVersionV1 {
		t.Fatalf("pre-rotation blob: %v version=%d", err, pre[0])
	}

	// Rotate twice.
	key.Materials = []KeyMaterial{{ID: "m1", Raw: bytes.Repeat([]byte{2}, 32)}, {ID: "m2", Raw: bytes.Repeat([]byte{3}, 32)}}
	key.CurrentMaterialID = "m1"
	mid, _ := key.EncryptBlob([]byte("mid"), aad)
	key.CurrentMaterialID = "m2"
	post, _ := key.EncryptBlob([]byte("post"), aad)
	if p := cryptoutil.ParseCipherBlob(post); p.MaterialID != "m2" {
		t.Fatalf("post-rotation blob names %q, want m2", p.MaterialID)
	}

	for want, blob := range map[string][]byte{"legacy": legacy, "v1": v1, "pre": pre, "mid": mid, "post": post} {
		got, err := key.DecryptBlob(blob, aad)
		if err != nil || string(got) != want {
			t.Fatalf("decrypt %s: %q %v", want, got, err)
		}
		if _, err := key.DecryptBlob(blob, nil); err == nil {
			t.Fatalf("decrypt %s with wrong context succeeded", want)
		}
	}
	// A blob naming a material version the key does not have fails.
	other := KMSKey{ID: "k1", MasterKeyRaw: orig}
	if _, err := other.DecryptBlob(post, aad); err == nil {
		t.Fatal("decrypt with missing material version succeeded")
	}
}

func TestNormalizeTags(t *testing.T) {
	if _, err := NormalizeTags([]KMSTag{{Key: "team", Value: "core"}}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]KMSTag{nil, {{Key: ""}}, {{Key: "aws:x"}}, {{Key: "a"}, {Key: "a"}}, {{Key: string(make([]byte, 129))}}} {
		if _, err := NormalizeTags(bad); err == nil {
			t.Fatalf("NormalizeTags(%v) accepted", bad)
		}
	}
}
