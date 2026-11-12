package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/config"
	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/memory"
)

func devKMSServer(t *testing.T) (*Server, *memory.Store, http.Handler) {
	t.Helper()
	st := &memory.Store{AccountID: "000000000000"}
	s := &Server{cfg: config.Config{InsecureDev: true}, store: st}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleKMS)
	return s, st, mux
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestAWSKeyRotationLifecycle(t *testing.T) {
	_, _, h := devKMSServer(t)
	key := callKMS(t, h, "TrentService.CreateKey", map[string]any{})["KeyMetadata"].(map[string]any)
	keyID := key["KeyId"].(string)

	before := callKMS(t, h, "TrentService.Encrypt", map[string]any{"KeyId": keyID, "Plaintext": b64("before"), "EncryptionContext": map[string]string{"a": "b"}})["CiphertextBlob"].(string)
	dataKey := callKMS(t, h, "TrentService.GenerateDataKey", map[string]any{"KeyId": keyID, "KeySpec": "AES_256"})

	st := callKMS(t, h, "TrentService.GetKeyRotationStatus", map[string]any{"KeyId": keyID})
	if st["KeyRotationEnabled"] != false {
		t.Fatalf("status before enable: %v", st)
	}
	rec := post(t, h, "TrentService.EnableKeyRotation", map[string]any{"KeyId": keyID, "RotationPeriodInDays": 30})
	wantStatus(t, rec, http.StatusBadRequest)
	assertAWSErrorType(t, rec.Body.Bytes(), "ValidationException")
	callKMS(t, h, "TrentService.EnableKeyRotation", map[string]any{"KeyId": keyID, "RotationPeriodInDays": 180})
	st = callKMS(t, h, "TrentService.GetKeyRotationStatus", map[string]any{"KeyId": keyID})
	if st["KeyRotationEnabled"] != true || st["RotationPeriodInDays"] != float64(180) || st["NextRotationDate"] == nil {
		t.Fatalf("status after enable: %v", st)
	}
	if _, isNum := st["NextRotationDate"].(float64); !isNum {
		t.Fatalf("NextRotationDate should be epoch seconds: %v", st["NextRotationDate"])
	}

	callKMS(t, h, "TrentService.RotateKeyOnDemand", map[string]any{"KeyId": keyID})
	rots := callKMS(t, h, "TrentService.ListKeyRotations", map[string]any{"KeyId": keyID})["Rotations"].([]any)
	if len(rots) != 1 || rots[0].(map[string]any)["RotationType"] != "ON_DEMAND" {
		t.Fatalf("rotations %v", rots)
	}

	// New ciphertext uses the new material version; old ciphertext and old
	// data keys still decrypt.
	after := callKMS(t, h, "TrentService.Encrypt", map[string]any{"KeyId": keyID, "Plaintext": b64("after")})["CiphertextBlob"].(string)
	raw, _ := base64.StdEncoding.DecodeString(after)
	if p := cryptoutil.ParseCipherBlob(raw); p.Version != cryptoutil.CipherBlobVersionV2 || p.MaterialID == "" {
		t.Fatalf("post-rotation blob is not v2: %+v", p)
	}
	for _, c := range []struct {
		blob, want string
		ctx        map[string]string
	}{{before, "before", map[string]string{"a": "b"}}, {after, "after", nil}} {
		got := callKMS(t, h, "TrentService.Decrypt", map[string]any{"CiphertextBlob": c.blob, "EncryptionContext": c.ctx})["Plaintext"].(string)
		if got != b64(c.want) {
			t.Fatalf("decrypt %s: %s", c.want, got)
		}
	}
	got := callKMS(t, h, "TrentService.Decrypt", map[string]any{"CiphertextBlob": dataKey["CiphertextBlob"]})["Plaintext"]
	if got != dataKey["Plaintext"] {
		t.Fatal("pre-rotation data key no longer decrypts")
	}
	// ReEncrypt moves an old blob onto the current material.
	re := callKMS(t, h, "TrentService.ReEncrypt", map[string]any{"CiphertextBlob": before, "SourceEncryptionContext": map[string]string{"a": "b"}, "DestinationKeyId": keyID})["CiphertextBlob"].(string)
	raw, _ = base64.StdEncoding.DecodeString(re)
	if p := cryptoutil.ParseCipherBlob(raw); p.Version != cryptoutil.CipherBlobVersionV2 {
		t.Fatalf("ReEncrypt output is not v2: %+v", p)
	}
	if callKMS(t, h, "TrentService.Decrypt", map[string]any{"CiphertextBlob": re})["Plaintext"] != b64("before") {
		t.Fatal("re-encrypted blob does not decrypt")
	}

	callKMS(t, h, "TrentService.DisableKeyRotation", map[string]any{"KeyId": keyID})
	if callKMS(t, h, "TrentService.GetKeyRotationStatus", map[string]any{"KeyId": keyID})["KeyRotationEnabled"] != false {
		t.Fatal("rotation still enabled")
	}
}

func TestAWSRotationRefusedForAsymmetricKeys(t *testing.T) {
	_, _, h := devKMSServer(t)
	key := callKMS(t, h, "TrentService.CreateKey", map[string]any{"KeyUsage": "SIGN_VERIFY", "KeySpec": "ECC_NIST_P256"})["KeyMetadata"].(map[string]any)
	rec := post(t, h, "TrentService.EnableKeyRotation", map[string]any{"KeyId": key["KeyId"]})
	wantStatus(t, rec, http.StatusBadRequest)
	assertAWSErrorType(t, rec.Body.Bytes(), "UnsupportedOperationException")
}

func TestAWSRSAEncryptionKey(t *testing.T) {
	_, _, h := devKMSServer(t)
	key := callKMS(t, h, "TrentService.CreateKey", map[string]any{"KeyUsage": "ENCRYPT_DECRYPT", "KeySpec": "RSA_2048"})["KeyMetadata"].(map[string]any)
	keyID := key["KeyId"].(string)
	if algs, _ := key["EncryptionAlgorithms"].([]any); len(algs) != 1 || algs[0] != "RSAES_OAEP_SHA_256" {
		t.Fatalf("encryption algorithms %v", key["EncryptionAlgorithms"])
	}
	// The algorithm is required for an asymmetric key, and SHA-1 OAEP is not offered.
	rec := post(t, h, "TrentService.Encrypt", map[string]any{"KeyId": keyID, "Plaintext": b64("x")})
	wantStatus(t, rec, http.StatusBadRequest)
	rec = post(t, h, "TrentService.Encrypt", map[string]any{"KeyId": keyID, "Plaintext": b64("x"), "EncryptionAlgorithm": "RSAES_OAEP_SHA_1"})
	wantStatus(t, rec, http.StatusBadRequest)
	rec = post(t, h, "TrentService.Encrypt", map[string]any{"KeyId": keyID, "Plaintext": base64.StdEncoding.EncodeToString(make([]byte, 191)), "EncryptionAlgorithm": "RSAES_OAEP_SHA_256"})
	wantStatus(t, rec, http.StatusBadRequest)

	enc := callKMS(t, h, "TrentService.Encrypt", map[string]any{"KeyId": keyID, "Plaintext": b64("rsa secret"), "EncryptionAlgorithm": "RSAES_OAEP_SHA_256"})
	if enc["EncryptionAlgorithm"] != "RSAES_OAEP_SHA_256" {
		t.Fatalf("encrypt response %v", enc)
	}
	rec = post(t, h, "TrentService.Decrypt", map[string]any{"CiphertextBlob": enc["CiphertextBlob"], "EncryptionAlgorithm": "RSAES_OAEP_SHA_256"})
	wantStatus(t, rec, http.StatusBadRequest) // KeyId required
	dec := callKMS(t, h, "TrentService.Decrypt", map[string]any{"KeyId": keyID, "CiphertextBlob": enc["CiphertextBlob"], "EncryptionAlgorithm": "RSAES_OAEP_SHA_256"})
	if dec["Plaintext"] != b64("rsa secret") {
		t.Fatalf("decrypt %v", dec)
	}
	pub := callKMS(t, h, "TrentService.GetPublicKey", map[string]any{"KeyId": keyID})
	if pub["KeyUsage"] != "ENCRYPT_DECRYPT" || pub["PublicKey"] == "" {
		t.Fatalf("GetPublicKey %v", pub)
	}
	// Data keys need a symmetric key.
	rec = post(t, h, "TrentService.GenerateDataKey", map[string]any{"KeyId": keyID, "KeySpec": "AES_256"})
	wantStatus(t, rec, http.StatusBadRequest)
	assertAWSErrorType(t, rec.Body.Bytes(), "InvalidKeyUsageException")
}

func TestAWSTagsAndGenerateRandom(t *testing.T) {
	_, _, h := devKMSServer(t)
	keyID := callKMS(t, h, "TrentService.CreateKey", map[string]any{})["KeyMetadata"].(map[string]any)["KeyId"].(string)
	callKMS(t, h, "TrentService.TagResource", map[string]any{"KeyId": keyID, "Tags": []map[string]string{{"TagKey": "team", "TagValue": "core"}}})
	tags := callKMS(t, h, "TrentService.ListResourceTags", map[string]any{"KeyId": keyID})["Tags"].([]any)
	if len(tags) != 1 || tags[0].(map[string]any)["TagValue"] != "core" {
		t.Fatalf("tags %v", tags)
	}
	rec := post(t, h, "TrentService.TagResource", map[string]any{"KeyId": keyID, "Tags": []map[string]string{{"TagKey": "aws:reserved", "TagValue": "x"}}})
	wantStatus(t, rec, http.StatusBadRequest)
	assertAWSErrorType(t, rec.Body.Bytes(), "TagException")
	callKMS(t, h, "TrentService.UntagResource", map[string]any{"KeyId": keyID, "TagKeys": []string{"team"}})
	if tags := callKMS(t, h, "TrentService.ListResourceTags", map[string]any{"KeyId": keyID})["Tags"].([]any); len(tags) != 0 {
		t.Fatalf("tags after untag %v", tags)
	}

	r := callKMS(t, h, "TrentService.GenerateRandom", map[string]any{"NumberOfBytes": 32})
	raw, err := base64.StdEncoding.DecodeString(r["Plaintext"].(string))
	if err != nil || len(raw) != 32 {
		t.Fatalf("GenerateRandom: %d bytes %v", len(raw), err)
	}
	for _, n := range []int{0, 1025} {
		rec := post(t, h, "TrentService.GenerateRandom", map[string]any{"NumberOfBytes": n})
		wantStatus(t, rec, http.StatusBadRequest)
	}
}

// postAs sends an unsigned request whose Authorization header names an
// access key; in insecure dev mode that becomes the policy principal
// arn:aws:iam::000000000000:user/<accessKey>.
func postAs(t *testing.T, h http.Handler, accessKey, target string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b))
	req.Header.Set("X-Amz-Target", target)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+accessKey+"/20260101/us-east-1/kms/aws4_request")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestGrantsAuthorizeOperations(t *testing.T) {
	s, _, h := devKMSServer(t)
	s.cfg.DefaultDenyPolicy = true
	keyID := callKMS(t, h, "TrentService.CreateKey", map[string]any{})["KeyMetadata"].(map[string]any)["KeyId"].(string)
	// Only the admin principal is allowed by the key policy.
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:user/ADMIN"},"Action":"kms:*","Resource":"*"}]}`
	wantStatus(t, postAs(t, h, "ADMIN", "TrentService.PutKeyPolicy", map[string]any{"KeyId": keyID, "PolicyName": "default", "Policy": policy}), http.StatusOK)

	enc := map[string]any{"KeyId": keyID, "Plaintext": b64("hi")}
	rec := postAs(t, h, "APP", "TrentService.Encrypt", enc)
	wantStatus(t, rec, http.StatusBadRequest)
	assertAWSErrorType(t, rec.Body.Bytes(), "AccessDeniedException")

	// Invalid grants are refused.
	for _, bad := range []map[string]any{
		{"KeyId": keyID, "GranteePrincipal": "*", "Operations": []string{"Encrypt"}},
		{"KeyId": keyID, "GranteePrincipal": "arn:aws:iam::000000000000:user/APP", "Operations": []string{"Sign"}},
		{"KeyId": keyID, "GranteePrincipal": "arn:aws:iam::000000000000:user/APP", "Operations": []string{"Bogus"}},
	} {
		wantStatus(t, postAs(t, h, "ADMIN", "TrentService.CreateGrant", bad), http.StatusBadRequest)
	}
	rec = postAs(t, h, "ADMIN", "TrentService.CreateGrant", map[string]any{"KeyId": keyID, "GranteePrincipal": "arn:aws:iam::000000000000:user/APP", "Operations": []string{"Encrypt"}})
	wantStatus(t, rec, http.StatusOK)
	grantID := decode(t, rec)["GrantId"].(string)

	rec = postAs(t, h, "APP", "TrentService.Encrypt", enc)
	wantStatus(t, rec, http.StatusOK)
	blob := decode(t, rec)["CiphertextBlob"]
	// The grant covers Encrypt only.
	rec = postAs(t, h, "APP", "TrentService.Decrypt", map[string]any{"CiphertextBlob": blob})
	assertAWSErrorType(t, rec.Body.Bytes(), "AccessDeniedException")
	// Another principal gets nothing from APP's grant, and cannot retire it.
	assertAWSErrorType(t, postAs(t, h, "OTHER", "TrentService.Encrypt", enc).Body.Bytes(), "AccessDeniedException")
	assertAWSErrorType(t, postAs(t, h, "OTHER", "TrentService.RetireGrant", map[string]any{"GrantId": grantID}).Body.Bytes(), "AccessDeniedException")

	// An explicit Deny in the key policy overrides the grant.
	deny := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:user/ADMIN"},"Action":"kms:*","Resource":"*"},{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::000000000000:user/APP"},"Action":"kms:Encrypt","Resource":"*"}]}`
	wantStatus(t, postAs(t, h, "ADMIN", "TrentService.PutKeyPolicy", map[string]any{"KeyId": keyID, "PolicyName": "default", "Policy": deny}), http.StatusOK)
	assertAWSErrorType(t, postAs(t, h, "APP", "TrentService.Encrypt", enc).Body.Bytes(), "AccessDeniedException")

	// Revoked grants stop authorizing.
	wantStatus(t, postAs(t, h, "ADMIN", "TrentService.PutKeyPolicy", map[string]any{"KeyId": keyID, "PolicyName": "default", "Policy": policy}), http.StatusOK)
	wantStatus(t, postAs(t, h, "ADMIN", "TrentService.RevokeGrant", map[string]any{"KeyId": keyID, "GrantId": grantID}), http.StatusOK)
	assertAWSErrorType(t, postAs(t, h, "APP", "TrentService.Encrypt", enc).Body.Bytes(), "AccessDeniedException")
}

func TestKMSJobRotatesAndDeletes(t *testing.T) {
	s, st, _ := devKMSServer(t)
	ctx := store.WithCallerAccount(context.Background(), "111111111111")
	rot, err := st.CreateKey(ctx, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	k, err := st.SetKeyRotation(ctx, rot.ID, true, 90)
	if err != nil {
		t.Fatal(err)
	}
	doomed, _ := st.CreateKey(ctx, "", "", "")
	if _, _, err := st.CreateSecret(ctx, store.CreateSecretRequest{Name: "still/used", SecretString: "v", KMSKeyID: doomed.ID}); err != nil {
		t.Fatal(err)
	}
	when, err := st.ScheduleKeyDeletion(ctx, doomed.ID, 7)
	if err != nil {
		t.Fatal(err)
	}

	s.runKMSJobsOnce(context.Background(), time.Now().UTC())
	if hist, _ := st.ListKeyRotations(ctx, rot.ID); len(hist) != 0 {
		t.Fatalf("rotated before due: %+v", hist)
	}
	future := k.NextRotationAt.Add(time.Minute)
	if when.After(future) {
		future = when.Add(time.Minute)
	}
	s.runKMSJobsOnce(context.Background(), future)
	if hist, _ := st.ListKeyRotations(ctx, rot.ID); len(hist) != 1 || hist[0].Kind != store.RotationKindAutomatic {
		t.Fatalf("automatic rotation: %+v", hist)
	}
	if _, err := st.ResolveByID(ctx, doomed.ID); err == nil {
		t.Fatal("expired key was not destroyed")
	}
	if !auditedIn(t, st, "kms.RotateKey", "ok", kmsJobActor, "111111111111") {
		t.Fatal("rotation not audited")
	}
	if !auditedIn(t, st, "kms.DeleteKey", "ok", kmsJobActor, "111111111111") {
		t.Fatal("deletion not audited")
	}
	// A second run is a no-op.
	s.runKMSJobsOnce(context.Background(), future)
	if hist, _ := st.ListKeyRotations(ctx, rot.ID); len(hist) != 1 {
		t.Fatalf("second run rotated again: %+v", hist)
	}
}

func TestAWSDecryptLegacyBlobAfterRotation(t *testing.T) {
	k := sampleKey(3)
	st := &memory.Store{DefaultKey: k}
	s := &Server{cfg: config.Config{InsecureDev: true}, store: st}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleKMS)
	legacy, _ := cryptoutil.EncryptLegacyBlob(k.MasterKeyRaw, []byte("legacy"), nil)
	v1, _ := cryptoutil.EncryptBlob(k.MasterKeyRaw, k.ID, []byte("v1"), nil)
	if _, err := st.RotateKeyMaterial(context.Background(), k.ID, store.RotationKindOnDemand, time.Now()); err != nil {
		t.Fatal(err)
	}
	for want, blob := range map[string][]byte{"legacy": legacy, "v1": v1} {
		got := callKMS(t, mux, "TrentService.Decrypt", map[string]any{"CiphertextBlob": base64.StdEncoding.EncodeToString(blob)})["Plaintext"]
		if got != b64(want) {
			t.Fatalf("%s blob after rotation: %v", want, got)
		}
	}
	_ = sha256.Size
}
