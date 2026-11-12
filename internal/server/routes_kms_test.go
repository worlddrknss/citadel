package server

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
)

// kmsEnv is an authEnv with one symmetric key in account A.
func kmsEnv(t *testing.T) (*authEnv, store.KMSKey) {
	t.Helper()
	e := newAuthEnv(t)
	k, err := e.st.CreateKey(store.WithCallerAccount(context.Background(), e.acctA), "app", "", "")
	if err != nil {
		t.Fatal(err)
	}
	return e, k
}

func TestV1KMSRotation(t *testing.T) {
	e, k := kmsEnv(t)
	bobA := e.session("bob", e.acctA)
	q := "/v1/kms/keys/rotation?keyId=" + url.QueryEscape(k.ID)

	rec := e.do(http.MethodGet, q, nil, bobA)
	wantStatus(t, rec, http.StatusOK)
	if m := decode(t, rec); m["supported"] != true || m["enabled"] != false || m["rotationPeriodDays"] != float64(365) {
		t.Fatalf("initial status %v", m)
	}
	// Validation.
	wantStatus(t, e.do(http.MethodPost, "/v1/kms/keys/rotation", map[string]any{"keyId": k.ID, "enabled": true, "rotationPeriodDays": 30}, bobA), http.StatusBadRequest)
	wantStatus(t, e.do(http.MethodPost, "/v1/kms/keys/rotation", map[string]any{"enabled": true}, bobA), http.StatusBadRequest)
	// Role denial: bob is only a viewer in B; carol is a viewer in B.
	wantStatus(t, e.do(http.MethodPost, "/v1/kms/keys/rotation", map[string]any{"keyId": k.ID, "enabled": true}, e.session("bob", e.acctB)), http.StatusForbidden)
	// Cross-account: account B cannot see the key at all.
	wantStatus(t, e.do(http.MethodGet, q, nil, e.session("carol", e.acctB)), http.StatusNotFound)
	wantStatus(t, e.do(http.MethodGet, q, nil, e.session("root", e.acctB)), http.StatusNotFound)

	rec = e.do(http.MethodPost, "/v1/kms/keys/rotation", map[string]any{"keyId": k.ID, "enabled": true, "rotationPeriodDays": 90}, bobA)
	wantStatus(t, rec, http.StatusOK)
	if m := decode(t, rec); m["enabled"] != true || m["rotationPeriodDays"] != float64(90) || m["nextRotationAt"] == nil {
		t.Fatalf("after enable %v", m)
	}
	if !e.audited("kms.EnableKeyRotation", "ok") {
		t.Fatal("enable not audited")
	}
	rec = e.do(http.MethodPost, "/v1/kms/keys/rotate", map[string]any{"keyId": k.ID}, bobA)
	wantStatus(t, rec, http.StatusOK)
	m := decode(t, rec)
	hist, _ := m["history"].([]any)
	if len(hist) != 1 || hist[0].(map[string]any)["kind"] != "on-demand" || m["lastRotatedAt"] == nil {
		t.Fatalf("history %v", m)
	}
	wantStatus(t, e.do(http.MethodPost, "/v1/kms/keys/rotation", map[string]any{"keyId": k.ID, "enabled": false}, bobA), http.StatusOK)
	if !e.audited("kms.DisableKeyRotation", "ok") {
		t.Fatal("disable not audited")
	}

	// List and detail carry the rotation summary, managed, origin, usedBy.
	rec = e.do(http.MethodGet, "/v1/kms/keys", nil, bobA)
	wantStatus(t, rec, http.StatusOK)
	found := false
	for _, it := range decode(t, rec)["keys"].([]any) {
		item := it.(map[string]any)
		if item["keyId"] == k.ID {
			found = true
			if item["managed"] != false || item["origin"] != "AWS_KMS" || item["rotation"].(map[string]any)["enabled"] != false {
				t.Fatalf("list item %v", item)
			}
		}
	}
	if !found {
		t.Fatal("key not listed")
	}
	if _, _, err := e.st.CreateSecret(store.WithCallerAccount(context.Background(), e.acctA), store.CreateSecretRequest{Name: "app/prod/X", SecretString: "v", KMSKeyID: k.ID}); err != nil {
		t.Fatal(err)
	}
	rec = e.do(http.MethodGet, "/v1/kms/keys/detail?keyId="+url.QueryEscape(k.ID), nil, bobA)
	wantStatus(t, rec, http.StatusOK)
	d := decode(t, rec)
	if ub, _ := d["usedBy"].(map[string]any); ub == nil || ub["secrets"] != float64(1) || d["origin"] != "AWS_KMS" {
		t.Fatalf("detail %v", d)
	}
}

func TestV1KMSRotationAsymmetric(t *testing.T) {
	e := newAuthEnv(t)
	k, err := e.st.CreateKey(store.WithCallerAccount(context.Background(), e.acctA), "", store.KeyUsageSignVerify, store.KeySpecECCP256)
	if err != nil {
		t.Fatal(err)
	}
	bobA := e.session("bob", e.acctA)
	rec := e.do(http.MethodGet, "/v1/kms/keys/rotation?keyId="+k.ID, nil, bobA)
	wantStatus(t, rec, http.StatusOK)
	if decode(t, rec)["supported"] != false {
		t.Fatal("asymmetric key reported as rotatable")
	}
	wantStatus(t, e.do(http.MethodPost, "/v1/kms/keys/rotation", map[string]any{"keyId": k.ID, "enabled": true}, bobA), http.StatusBadRequest)
}

func TestV1KMSTags(t *testing.T) {
	e, k := kmsEnv(t)
	bobA := e.session("bob", e.acctA)
	wantStatus(t, e.do(http.MethodPost, "/v1/kms/keys/tags", map[string]any{"keyId": k.ID, "tags": []map[string]string{{"key": "team", "value": "core"}}}, bobA), http.StatusOK)
	wantStatus(t, e.do(http.MethodPost, "/v1/kms/keys/tags", map[string]any{"keyId": k.ID, "tags": []map[string]string{{"key": "aws:x", "value": "y"}}}, bobA), http.StatusBadRequest)
	wantStatus(t, e.do(http.MethodPost, "/v1/kms/keys/tags", map[string]any{"keyId": k.ID, "tags": []map[string]string{{"key": "x", "value": "y"}}}, e.session("bob", e.acctB)), http.StatusForbidden)
	wantStatus(t, e.do(http.MethodGet, "/v1/kms/keys/tags?keyId="+k.ID, nil, e.session("carol", e.acctB)), http.StatusNotFound)
	rec := e.do(http.MethodGet, "/v1/kms/keys/tags?keyId="+k.ID, nil, e.session("alice", e.acctA))
	wantStatus(t, rec, http.StatusOK)
	tags := decode(t, rec)["tags"].([]any)
	if len(tags) != 1 || tags[0].(map[string]any)["value"] != "core" {
		t.Fatalf("tags %v", tags)
	}
	rec = e.do(http.MethodDelete, "/v1/kms/keys/tags?keyId="+k.ID+"&tagKey=team", nil, bobA)
	wantStatus(t, rec, http.StatusOK)
	if decode(t, rec)["untagged"] != true || !e.audited("kms.TagResource", "ok") || !e.audited("kms.UntagResource", "ok") {
		t.Fatal("untag response or audit missing")
	}
}

func TestV1KMSGrants(t *testing.T) {
	e, k := kmsEnv(t)
	bobA := e.session("bob", e.acctA)
	good := map[string]any{"keyId": k.ID, "granteePrincipal": "arn:aws:iam::" + e.acctA + ":user/app", "operations": []string{"Encrypt", "Decrypt"}, "name": "app-grant"}
	wantStatus(t, e.do(http.MethodPost, "/v1/kms/grants", good, e.session("bob", e.acctB)), http.StatusForbidden)
	wantStatus(t, e.do(http.MethodPost, "/v1/kms/grants", good, e.session("root", e.acctB)), http.StatusNotFound)
	for _, bad := range []map[string]any{
		{"keyId": k.ID, "granteePrincipal": "app", "operations": []string{"Encrypt"}},
		{"keyId": k.ID, "granteePrincipal": "arn:aws:iam::1:user/a", "operations": []string{}},
		{"keyId": k.ID, "granteePrincipal": "arn:aws:iam::1:user/a", "operations": []string{"Sign"}},
	} {
		wantStatus(t, e.do(http.MethodPost, "/v1/kms/grants", bad, bobA), http.StatusBadRequest)
	}
	rec := e.do(http.MethodPost, "/v1/kms/grants", good, bobA)
	wantStatus(t, rec, http.StatusOK)
	m := decode(t, rec)
	grantID, _ := m["grantId"].(string)
	if grantID == "" || m["grantToken"] == "" {
		t.Fatalf("create grant %v", m)
	}
	rec = e.do(http.MethodGet, "/v1/kms/keys/detail?keyId="+k.ID, nil, bobA)
	if gs := decode(t, rec)["grants"].([]any); len(gs) != 1 {
		t.Fatalf("detail grants %v", gs)
	}
	wantStatus(t, e.do(http.MethodDelete, "/v1/kms/grants?keyId="+k.ID+"&grantId="+grantID, nil, e.session("root", e.acctB)), http.StatusNotFound)
	rec = e.do(http.MethodDelete, "/v1/kms/grants?keyId="+k.ID+"&grantId="+grantID, nil, bobA)
	wantStatus(t, rec, http.StatusOK)
	if decode(t, rec)["revoked"] != true {
		t.Fatal("revoke response")
	}
	wantStatus(t, e.do(http.MethodDelete, "/v1/kms/grants?keyId="+k.ID+"&grantId="+grantID, nil, bobA), http.StatusNotFound)
	if !e.audited("kms.CreateGrant", "ok") || !e.audited("kms.RevokeGrant", "ok") {
		t.Fatal("grant audit missing")
	}
}

func TestV1KMSCrypto(t *testing.T) {
	e, k := kmsEnv(t)
	ctxA := store.WithCallerAccount(context.Background(), e.acctA)
	bobA := e.session("bob", e.acctA)
	pt := base64.StdEncoding.EncodeToString([]byte("hello"))

	// Viewers cannot use crypto.
	wantStatus(t, e.do(http.MethodPost, "/v1/kms/encrypt", map[string]any{"keyId": k.ID, "plaintext": pt, "encryptionAlgorithm": "SYMMETRIC_DEFAULT"}, e.session("bob", e.acctB)), http.StatusForbidden)
	wantStatus(t, e.do(http.MethodPost, "/v1/kms/encrypt", map[string]any{"keyId": k.ID, "plaintext": pt}, e.session("root", e.acctB)), http.StatusNotFound)
	wantStatus(t, e.do(http.MethodPost, "/v1/kms/encrypt", map[string]any{"keyId": k.ID, "plaintext": "%%%"}, bobA), http.StatusBadRequest)

	rec := e.do(http.MethodPost, "/v1/kms/encrypt", map[string]any{"keyId": k.ID, "plaintext": pt, "encryptionContext": map[string]string{"a": "b"}, "encryptionAlgorithm": "SYMMETRIC_DEFAULT"}, bobA)
	wantStatus(t, rec, http.StatusOK)
	blob := decode(t, rec)["ciphertextBlob"]
	// Rotate, then the old blob still decrypts.
	if _, err := e.st.RotateKeyMaterial(ctxA, k.ID, store.RotationKindOnDemand, k.CreatedAt); err != nil {
		t.Fatal(err)
	}
	rec = e.do(http.MethodPost, "/v1/kms/decrypt", map[string]any{"keyId": k.ID, "ciphertextBlob": blob, "encryptionContext": map[string]string{"a": "b"}, "encryptionAlgorithm": "SYMMETRIC_DEFAULT"}, bobA)
	wantStatus(t, rec, http.StatusOK)
	if decode(t, rec)["plaintext"] != pt {
		t.Fatal("decrypt mismatch")
	}
	wantStatus(t, e.do(http.MethodPost, "/v1/kms/decrypt", map[string]any{"keyId": k.ID, "ciphertextBlob": blob, "encryptionAlgorithm": "SYMMETRIC_DEFAULT"}, bobA), http.StatusBadRequest)
	if !e.audited("kms.Encrypt", "ok") || !e.audited("kms.Decrypt", "ok") {
		t.Fatal("crypto not audited")
	}

	// RSA encryption key.
	rsaKey, err := e.st.CreateKey(ctxA, "", store.KeyUsageEncryptDecrypt, store.KeySpecRSA3072)
	if err != nil {
		t.Fatal(err)
	}
	rec = e.do(http.MethodPost, "/v1/kms/encrypt", map[string]any{"keyId": rsaKey.ID, "plaintext": pt, "encryptionAlgorithm": "RSAES_OAEP_SHA_256"}, bobA)
	wantStatus(t, rec, http.StatusOK)
	rblob := decode(t, rec)["ciphertextBlob"]
	rec = e.do(http.MethodPost, "/v1/kms/decrypt", map[string]any{"keyId": rsaKey.ID, "ciphertextBlob": rblob, "encryptionAlgorithm": "RSAES_OAEP_SHA_256"}, bobA)
	wantStatus(t, rec, http.StatusOK)
	if decode(t, rec)["plaintext"] != pt {
		t.Fatal("RSA decrypt mismatch")
	}

	// Signing: ECDSA and RSASSA-PSS.
	for _, c := range []struct{ spec, alg string }{{store.KeySpecECCP384, "ECDSA_SHA_384"}, {store.KeySpecRSA2048, "RSASSA_PSS_SHA_256"}, {store.KeySpecRSA2048, "RSASSA_PKCS1_V1_5_SHA_512"}} {
		sk, err := e.st.CreateKey(ctxA, "", store.KeyUsageSignVerify, c.spec)
		if err != nil {
			t.Fatal(err)
		}
		body := map[string]any{"keyId": sk.ID, "message": pt, "messageType": "RAW", "signingAlgorithm": c.alg}
		rec := e.do(http.MethodPost, "/v1/kms/sign", body, bobA)
		wantStatus(t, rec, http.StatusOK)
		body["signature"] = decode(t, rec)["signature"]
		rec = e.do(http.MethodPost, "/v1/kms/verify", body, bobA)
		wantStatus(t, rec, http.StatusOK)
		if decode(t, rec)["signatureValid"] != true {
			t.Fatalf("%s signature invalid", c.alg)
		}
		body["message"] = base64.StdEncoding.EncodeToString([]byte("tampered"))
		rec = e.do(http.MethodPost, "/v1/kms/verify", body, bobA)
		wantStatus(t, rec, http.StatusOK)
		if decode(t, rec)["signatureValid"] != false {
			t.Fatalf("%s tampered message verified", c.alg)
		}
		// Wrong algorithm for the key, missing algorithm, short DIGEST.
		wantStatus(t, e.do(http.MethodPost, "/v1/kms/sign", map[string]any{"keyId": sk.ID, "message": pt, "messageType": "RAW", "signingAlgorithm": "ECDSA_SHA_512"}, bobA), http.StatusBadRequest)
		wantStatus(t, e.do(http.MethodPost, "/v1/kms/sign", map[string]any{"keyId": sk.ID, "message": pt, "messageType": "RAW"}, bobA), http.StatusBadRequest)
		wantStatus(t, e.do(http.MethodPost, "/v1/kms/sign", map[string]any{"keyId": sk.ID, "message": pt, "messageType": "DIGEST", "signingAlgorithm": c.alg}, bobA), http.StatusBadRequest)
	}
	// A symmetric key cannot sign.
	wantStatus(t, e.do(http.MethodPost, "/v1/kms/sign", map[string]any{"keyId": k.ID, "message": pt, "messageType": "RAW", "signingAlgorithm": "ECDSA_SHA_256"}, bobA), http.StatusBadRequest)
}

func TestV1KMSRewrapRequiresPlatformAdmin(t *testing.T) {
	e := newAuthEnv(t)
	wantStatus(t, e.do(http.MethodPost, "/v1/kms/admin/rewrap", nil, e.session("alice", e.acctA)), http.StatusForbidden)
	rec := e.do(http.MethodPost, "/v1/kms/admin/rewrap", nil, e.session("root", e.acctA))
	wantStatus(t, rec, http.StatusOK)
	m := decode(t, rec)
	for _, f := range []string{"keyMaterial", "accessKeySecrets", "stsSessionSecrets", "rewrapped", "failed"} {
		if _, ok := m[f]; !ok {
			t.Fatalf("missing %s in %v", f, m)
		}
	}
	if !e.audited("citadel.RewrapKeyMaterial", "ok") {
		t.Fatal("rewrap not audited")
	}
}
