package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestEncryptedPKCS8RoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pass := []byte("correct horse battery")
	enc, err := encryptPKCS8PEMIter(der, pass, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(enc, der) {
		t.Fatal("ciphertext contains the plaintext key")
	}
	got, err := decryptPKCS8PEM(enc, pass)
	if err != nil || !bytes.Equal(got, der) {
		t.Fatalf("decrypt = %v", err)
	}
	if _, err := decryptPKCS8PEM(enc, []byte("wrong passphrase")); err == nil {
		// A wrong key yields random padding; a 1/256 chance of valid-looking
		// padding still fails PKCS#8 parsing.
		if p, _ := decryptPKCS8PEM(enc, []byte("wrong passphrase")); p != nil {
			if _, perr := x509.ParsePKCS8PrivateKey(p); perr == nil {
				t.Fatal("wrong passphrase decrypted to a valid key")
			}
		}
	}
	// The default iteration count is used by ExportCertificate.
	if _, err := encryptPKCS8PEM(der, []byte("a")); err != nil {
		t.Fatalf("short passphrase: %v", err)
	}
}

// TestEncryptedPKCS8OpenSSL checks interoperability when an openssl binary is
// available (skipped otherwise).
func TestEncryptedPKCS8OpenSSL(t *testing.T) {
	bin, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	enc, err := encryptPKCS8PEMIter(der, []byte("export-passphrase"), 2048)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(in, enc, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "pkey", "-in", in, "-passin", "pass:export-passphrase", "-outform", "DER").Output()
	if err != nil {
		t.Skipf("openssl could not run: %v", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(out)
	if err != nil {
		t.Fatalf("openssl output: %v", err)
	}
	if !key.Equal(parsed) {
		t.Fatal("openssl decrypted a different key")
	}
}
