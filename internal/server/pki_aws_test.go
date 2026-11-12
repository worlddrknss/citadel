package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func awsCall(t *testing.T, h http.Handler, target string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", target)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec.Code, m
}

func mustAWS(t *testing.T, h http.Handler, target string, body any) map[string]any {
	t.Helper()
	code, m := awsCall(t, h, target, body)
	if code != http.StatusOK {
		t.Fatalf("%s: %d %v", target, code, m)
	}
	return m
}

// TestAWSPKITargets uses the X-Amz-Target values real SDKs send
// (CertificateManager.*, ACMPrivateCA.*) and the legacy aliases.
func TestAWSPKITargets(t *testing.T) {
	e := newPKIEnv(t, func(s *Server) { s.cfg.InsecureDev = true })
	h := e.h

	m := mustAWS(t, h, "ACMPrivateCA.CreateCertificateAuthority", map[string]any{
		"CertificateAuthorityType": "ROOT",
		"CertificateAuthorityConfiguration": map[string]any{"KeyAlgorithm": "EC_prime256v1", "SigningAlgorithm": "SHA256WITHECDSA",
			"Subject": map[string]any{"CommonName": "AWS Root", "Organization": "Citadel"}},
		"IdempotencyToken": "x", "Tags": []any{},
	})
	caARN := m["CertificateAuthorityArn"].(string)

	m = mustAWS(t, h, "ACMPrivateCA.DescribeCertificateAuthority", map[string]any{"CertificateAuthorityArn": caARN})
	desc := m["CertificateAuthority"].(map[string]any)
	if _, ok := desc["CreatedAt"].(float64); !ok || desc["Status"] != "ACTIVE" {
		t.Fatalf("describe = %v", desc)
	}
	mustAWS(t, h, "acm-pca.DescribeCertificateAuthority", map[string]any{"CertificateAuthorityArn": caARN}) // legacy alias
	m = mustAWS(t, h, "ACMPrivateCA.ListCertificateAuthorities", map[string]any{"MaxResults": 10})
	if len(m["CertificateAuthorities"].([]any)) != 1 {
		t.Fatalf("list = %v", m)
	}
	m = mustAWS(t, h, "ACMPrivateCA.GetCertificateAuthorityCertificate", map[string]any{"CertificateAuthorityArn": caARN})
	if !strings.Contains(m["Certificate"].(string), "BEGIN CERTIFICATE") {
		t.Fatalf("CA cert = %v", m)
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "svc.example.com"}, DNSNames: []string{"svc.example.com"}}, key)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	m = mustAWS(t, h, "ACMPrivateCA.IssueCertificate", map[string]any{
		"CertificateAuthorityArn": caARN, "Csr": csrPEM, "SigningAlgorithm": "SHA256WITHECDSA",
		"Validity":    map[string]any{"Value": 30, "Type": "DAYS"},
		"TemplateArn": "arn:aws:acm-pca:::template/EndEntityClientAuthCertificate/V1",
	})
	certARN := m["CertificateArn"].(string)
	m = mustAWS(t, h, "ACMPrivateCA.GetCertificate", map[string]any{"CertificateAuthorityArn": caARN, "CertificateArn": certARN})
	leaf := parsePEMChain(t, m["Certificate"].(string))[0]
	verifyChain(t, leaf, parsePEMChain(t, m["CertificateChain"].(string)), x509.ExtKeyUsageClientAuth)
	mustAWS(t, h, "ACMPrivateCA.RevokeCertificate", map[string]any{"CertificateAuthorityArn": caARN, "CertificateSerial": colonHex(leaf.SerialNumber), "RevocationReason": "KEY_COMPROMISE"})
	if code, m := awsCall(t, h, "ACMPrivateCA.RevokeCertificate", map[string]any{"CertificateAuthorityArn": caARN, "CertificateSerial": colonHex(leaf.SerialNumber)}); code != 400 || m["__type"] != "RequestAlreadyProcessedException" {
		t.Fatalf("second revoke = %d %v", code, m)
	}

	// ACM private certificate lifecycle.
	m = mustAWS(t, h, "CertificateManager.RequestCertificate", map[string]any{"DomainName": "app.example.com", "SubjectAlternativeNames": []string{"www.example.com"},
		"CertificateAuthorityArn": caARN, "KeyAlgorithm": "EC_prime256v1"})
	acmARN := m["CertificateArn"].(string)
	m = mustAWS(t, h, "CertificateManager.DescribeCertificate", map[string]any{"CertificateArn": acmARN})
	d := m["Certificate"].(map[string]any)
	if d["Type"] != "PRIVATE" || d["Status"] != "ISSUED" || d["KeyAlgorithm"] != "EC_prime256v1" {
		t.Fatalf("describe = %v", d)
	}
	m = mustAWS(t, h, "CertificateManager.ListCertificates", map[string]any{"CertificateStatuses": []string{"ISSUED"}})
	if len(m["CertificateSummaryList"].([]any)) != 1 {
		t.Fatalf("list = %v", m)
	}
	m = mustAWS(t, h, "CertificateManager.ExportCertificate", map[string]any{"CertificateArn": acmARN, "Passphrase": []byte("s3cret-pass")})
	acmLeaf := parsePEMChain(t, m["Certificate"].(string))[0]
	keyDER, err := decryptPKCS8PEM([]byte(m["PrivateKey"].(string)), []byte("s3cret-pass"))
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := x509.ParsePKCS8PrivateKey(keyDER)
	if !publicKeysEqual(priv.(*ecdsa.PrivateKey).Public(), acmLeaf.PublicKey) {
		t.Fatal("exported key does not match certificate")
	}
	if code, _ := awsCall(t, h, "CertificateManager.ExportCertificate", map[string]any{"CertificateArn": acmARN, "Passphrase": []byte("ab")}); code != 400 {
		t.Fatal("short passphrase accepted")
	}
	mustAWS(t, h, "CertificateManager.RenewCertificate", map[string]any{"CertificateArn": acmARN})
	m = mustAWS(t, h, "CertificateManager.GetCertificate", map[string]any{"CertificateArn": acmARN})
	renewed := parsePEMChain(t, m["Certificate"].(string))[0]
	if renewed.SerialNumber.Cmp(acmLeaf.SerialNumber) == 0 || !publicKeysEqual(renewed.PublicKey, acmLeaf.PublicKey) {
		t.Fatal("renewal did not re-issue for the same key")
	}

	// Import, then delete.
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	m = mustAWS(t, h, "CertificateManager.ImportCertificate", map[string]any{"Certificate": encodeCertificatePEM(acmLeaf.Raw), "PrivateKey": keyPEM})
	impARN := m["CertificateArn"].(string)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherDER, _ := x509.MarshalPKCS8PrivateKey(otherKey)
	if code, _ := awsCall(t, h, "CertificateManager.ImportCertificate", map[string]any{"Certificate": encodeCertificatePEM(acmLeaf.Raw), "PrivateKey": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherDER})}); code != 400 {
		t.Fatal("mismatched key imported")
	}
	if code, _ := awsCall(t, h, "CertificateManager.ExportCertificate", map[string]any{"CertificateArn": impARN, "Passphrase": []byte("s3cret-pass")}); code != 400 {
		t.Fatal("imported certificate exported")
	}
	mustAWS(t, h, "CertificateManager.DeleteCertificate", map[string]any{"CertificateArn": impARN})
	if code, m := awsCall(t, h, "CertificateManager.DescribeCertificate", map[string]any{"CertificateArn": impARN}); code != 400 || m["__type"] != "ResourceNotFoundException" {
		t.Fatalf("deleted cert = %d %v", code, m)
	}
	if code, m := awsCall(t, h, "CertificateManager.Bogus", map[string]any{}); code != 400 || m["__type"] != "UnknownOperationException" {
		t.Fatalf("unknown op = %d %v", code, m)
	}
	if code, _ := awsCall(t, h, "CertificateManager.RequestCertificate", map[string]any{"DomainName": "x.example.com"}); code != 400 {
		t.Fatal("public certificate request accepted")
	}
}
