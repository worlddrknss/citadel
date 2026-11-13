package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

func (e *pkiEnv) caRow(user, caID string) *nativeCertificate {
	e.t.Helper()
	for _, r := range e.listRows(user) {
		if r.Source == "pca-ca" && r.ID == caID {
			return &r
		}
	}
	return nil
}

func TestDeleteCertificates(t *testing.T) {
	e := newPKIEnv(t, nil)
	ca := e.createCA("admin", map[string]any{"caType": "ROOT", "keyAlgorithm": "EC_prime256v1", "commonName": "Del Root"})
	issue := func(cn string) string {
		rec := e.do("editor", "POST", "/v1/certificates/issue/generate", map[string]any{"caId": ca, "commonName": cn, "keyAlgorithm": "EC_prime256v1", "validityDays": 30})
		wantStatus(t, rec, http.StatusOK)
		return decode(t, rec)["certId"].(string)
	}
	live, revoked := issue("live.example.com"), issue("revoked.example.com")
	wantStatus(t, e.do("admin", "POST", "/v1/certificates/revoke", map[string]any{"certId": revoked, "reason": "Superseded"}), http.StatusOK)
	del := func(user, source, id string) *http.Response {
		rec := e.do(user, "DELETE", "/v1/certificates?"+url.Values{"source": {source}, "id": {id}}.Encode(), nil)
		return rec.Result()
	}

	if got := del("editor", "pca-cert", live).StatusCode; got != http.StatusForbidden {
		t.Fatalf("editor delete = %d", got)
	}
	if got := del("other", "pca-cert", live).StatusCode; got != http.StatusNotFound {
		t.Fatalf("other account delete = %d", got)
	}
	if got := del("admin", "pca-ca", ca).StatusCode; got != http.StatusBadRequest {
		t.Fatalf("CA through certificate delete = %d", got)
	}
	if got := del("admin", "nope", live).StatusCode; got != http.StatusBadRequest {
		t.Fatalf("unknown source = %d", got)
	}

	// A revoked certificate is just removed.
	rec := e.do("admin", "DELETE", "/v1/certificates?"+url.Values{"source": {"pca-cert"}, "id": {revoked}}.Encode(), nil)
	wantStatus(t, rec, http.StatusOK)
	if m := decode(t, rec); m["deleted"] != true || m["revoked"] != false {
		t.Fatalf("delete revoked = %v", m)
	}
	// A live one is revoked first so it can't stay trusted unseen.
	rec = e.do("admin", "DELETE", "/v1/certificates?"+url.Values{"source": {"pca-cert"}, "id": {live}}.Encode(), nil)
	wantStatus(t, rec, http.StatusOK)
	if m := decode(t, rec); m["revoked"] != true {
		t.Fatalf("delete live = %v", m)
	}
	ctx := store.WithCallerAccount(context.Background(), e.acctA)
	c, err := e.st.GetCertificate(ctx, live)
	if err != nil || c.Status != "REVOKED" || c.RevocationReason != "CessationOfOperation" || c.DeletedAt == nil {
		t.Fatalf("deleted live certificate = %+v %v", c, err)
	}
	for _, r := range e.listRows("admin") {
		if r.ID == live || r.ID == revoked {
			t.Fatalf("deleted certificate listed: %+v", r)
		}
	}
	wantStatus(t, e.do("viewer", "GET", "/v1/certificates/detail?source=pca-cert&id="+live, nil), http.StatusNotFound)
	if got := del("admin", "pca-cert", live).StatusCode; got != http.StatusNotFound {
		t.Fatalf("delete twice = %d", got)
	}
	// Both stay on the CRL.
	crl := e.do("viewer", "GET", "/crl/"+ca, nil)
	wantStatus(t, crl, http.StatusOK)
	if !e.audited("citadel.DeleteCertificate") {
		t.Fatal("delete not audited")
	}

	// Imported certificates through the same endpoint.
	root, rootKey := testCert(t, "Ext Root", true, nil, nil)
	leaf, _ := testCert(t, "imp.example.com", false, root, rootKey)
	arn := e.importACM(leaf, root)
	if got := del("admin", sourceACMImported, arn).StatusCode; got != http.StatusOK {
		t.Fatalf("delete imported = %d", got)
	}
	// Let's Encrypt needs the database-backed store.
	if got := del("admin", "lets-encrypt", "le-1").StatusCode; got != http.StatusNotImplemented {
		t.Fatalf("delete LE on memory store = %d", got)
	}
}

func TestCADeleteRestoreLifecycle(t *testing.T) {
	e := newPKIEnv(t, nil)
	root := e.createCA("admin", map[string]any{"caType": "ROOT", "keyAlgorithm": "EC_prime256v1", "commonName": "LC Root"})
	rec := e.do("editor", "POST", "/v1/certificates/issue/generate", map[string]any{"caId": root, "commonName": "svc.example.com", "keyAlgorithm": "EC_prime256v1", "validityDays": 30})
	wantStatus(t, rec, http.StatusOK)
	certID := decode(t, rec)["certId"].(string)
	post := func(user, path string, body map[string]any) (int, map[string]any) {
		rec := e.do(user, "POST", path, body)
		return rec.Code, decode(t, rec)
	}

	if row := e.caRow("viewer", root); row == nil || row.Outstanding == nil || *row.Outstanding != 1 {
		t.Fatalf("row = %+v", row)
	}
	if code, _ := post("editor", "/v1/certificates/authorities/delete", map[string]any{"caId": root}); code != http.StatusForbidden {
		t.Fatalf("editor delete = %d", code)
	}
	if code, _ := post("other", "/v1/certificates/authorities/delete", map[string]any{"caId": root}); code != http.StatusNotFound {
		t.Fatalf("other account delete = %d", code)
	}
	// Active: disable first.
	code, m := post("admin", "/v1/certificates/authorities/delete", map[string]any{"caId": root})
	if code != http.StatusConflict || !strings.Contains(m["message"].(string), "disable it") {
		t.Fatalf("delete active = %d %v", code, m)
	}
	code, m = post("admin", "/v1/certificates/authorities/status", map[string]any{"caId": root, "status": "DISABLED"})
	if code != http.StatusOK || m["status"] != "DISABLED" {
		t.Fatalf("disable = %d %v", code, m)
	}
	// Disabled CAs don't issue.
	rec = e.do("editor", "POST", "/v1/certificates/issue/generate", map[string]any{"caId": root, "commonName": "x.example.com", "keyAlgorithm": "EC_prime256v1"})
	wantStatus(t, rec, http.StatusConflict)
	// Outstanding certificates block deletion.
	code, m = post("admin", "/v1/certificates/authorities/delete", map[string]any{"caId": root})
	if code != http.StatusConflict || !strings.Contains(m["message"].(string), "1 certificate that is still valid; revoke it first") {
		t.Fatalf("delete with outstanding = %d %v", code, m)
	}
	wantStatus(t, e.do("admin", "POST", "/v1/certificates/revoke", map[string]any{"certId": certID, "reason": "CessationOfOperation"}), http.StatusOK)
	for _, days := range []int{6, 31} {
		if code, _ := post("admin", "/v1/certificates/authorities/delete", map[string]any{"caId": root, "permanentDeletionTimeInDays": days}); code != http.StatusBadRequest {
			t.Fatalf("days %d = %d", days, code)
		}
	}
	code, m = post("admin", "/v1/certificates/authorities/delete", map[string]any{"caId": root, "permanentDeletionTimeInDays": 7})
	if code != http.StatusOK || m["status"] != "DELETED" {
		t.Fatalf("delete = %d %v", code, m)
	}
	until, err := time.Parse(time.RFC3339, m["restorableUntil"].(string))
	if err != nil || until.Sub(time.Now()) < 7*24*time.Hour-time.Minute || until.Sub(time.Now()) > 7*24*time.Hour+time.Minute {
		t.Fatalf("restorableUntil = %v %v", m["restorableUntil"], err)
	}
	if row := e.caRow("viewer", root); row == nil || row.Status != "DELETED" || row.RestorableUntil == "" {
		t.Fatalf("deleted row = %+v", row)
	}
	// Deleted CAs can't be enabled; restore returns them to DISABLED.
	if code, _ := post("admin", "/v1/certificates/authorities/status", map[string]any{"caId": root, "status": "ACTIVE"}); code != http.StatusConflict {
		t.Fatalf("enable deleted = %d", code)
	}
	code, m = post("admin", "/v1/certificates/authorities/restore", map[string]any{"caId": root})
	if code != http.StatusOK || m["status"] != "DISABLED" || m["restorableUntil"] != nil {
		t.Fatalf("restore = %d %v", code, m)
	}
	if code, _ := post("admin", "/v1/certificates/authorities/restore", map[string]any{"caId": root}); code != http.StatusConflict {
		t.Fatalf("restore twice = %d", code)
	}
	for _, a := range []string{"citadel.UpdateCAStatus", "citadel.DeleteCA", "citadel.RestoreCA"} {
		if !e.audited(a) {
			t.Fatalf("%s not audited", a)
		}
	}

	// Delete again (default window) and purge once it has passed.
	code, m = post("admin", "/v1/certificates/authorities/delete", map[string]any{"caId": root})
	if code != http.StatusOK {
		t.Fatalf("delete again = %d %v", code, m)
	}
	until, _ = time.Parse(time.RFC3339, m["restorableUntil"].(string))
	if d := until.Sub(time.Now()); d < 29*24*time.Hour {
		t.Fatalf("default window = %v", d)
	}
	if n := e.s.purgeDeletedCAs(context.Background(), time.Now()); n != 0 {
		t.Fatalf("purged %d inside the window", n)
	}
	if n := e.s.purgeDeletedCAs(context.Background(), until.Add(time.Second)); n != 1 {
		t.Fatalf("purged %d after the window", n)
	}
	if e.caRow("admin", root) != nil {
		t.Fatal("purged CA still listed")
	}
	if !e.audited("citadel.PurgeCertificateAuthority") {
		t.Fatal("purge not audited")
	}
}

func TestAWSPCADeleteRestore(t *testing.T) {
	e := newPKIEnv(t, func(s *Server) { s.cfg.InsecureDev = true })
	h := e.h
	m := mustAWS(t, h, "ACMPrivateCA.CreateCertificateAuthority", map[string]any{
		"CertificateAuthorityType": "ROOT",
		"CertificateAuthorityConfiguration": map[string]any{"KeyAlgorithm": "EC_prime256v1", "SigningAlgorithm": "SHA256WITHECDSA",
			"Subject": map[string]any{"CommonName": "AWS LC Root"}},
	})
	caARN := m["CertificateAuthorityArn"].(string)

	if code, m := awsCall(t, h, "ACMPrivateCA.DeleteCertificateAuthority", map[string]any{"CertificateAuthorityArn": caARN}); code != 400 || m["__type"] != "InvalidStateException" {
		t.Fatalf("delete active = %d %v", code, m)
	}
	mustAWS(t, h, "ACMPrivateCA.UpdateCertificateAuthority", map[string]any{"CertificateAuthorityArn": caARN, "Status": "DISABLED"})
	if code, m := awsCall(t, h, "ACMPrivateCA.DeleteCertificateAuthority", map[string]any{"CertificateAuthorityArn": caARN, "PermanentDeletionTimeInDays": 3}); code != 400 || m["__type"] != "ValidationException" {
		t.Fatalf("bad window = %d %v", code, m)
	}
	mustAWS(t, h, "ACMPrivateCA.DeleteCertificateAuthority", map[string]any{"CertificateAuthorityArn": caARN, "PermanentDeletionTimeInDays": 10})
	d := mustAWS(t, h, "ACMPrivateCA.DescribeCertificateAuthority", map[string]any{"CertificateAuthorityArn": caARN})["CertificateAuthority"].(map[string]any)
	if d["Status"] != "DELETED" || d["RestorableUntil"] == nil {
		t.Fatalf("describe deleted = %v", d)
	}
	mustAWS(t, h, "ACMPrivateCA.RestoreCertificateAuthority", map[string]any{"CertificateAuthorityArn": caARN})
	d = mustAWS(t, h, "ACMPrivateCA.DescribeCertificateAuthority", map[string]any{"CertificateAuthorityArn": caARN})["CertificateAuthority"].(map[string]any)
	if d["Status"] != "DISABLED" || d["RestorableUntil"] != nil {
		t.Fatalf("describe restored = %v", d)
	}
	mustAWS(t, h, "ACMPrivateCA.UpdateCertificateAuthority", map[string]any{"CertificateAuthorityArn": caARN, "Status": "ACTIVE"})
	if code, m := awsCall(t, h, "ACMPrivateCA.UpdateCertificateAuthority", map[string]any{"CertificateAuthorityArn": caARN, "Status": "BOGUS"}); code != 400 {
		t.Fatalf("bad status = %d %v", code, m)
	}
	if code, m := awsCall(t, h, "ACMPrivateCA.RestoreCertificateAuthority", map[string]any{"CertificateAuthorityArn": caARN}); code != 400 || m["__type"] != "InvalidStateException" {
		t.Fatalf("restore active = %d %v", code, m)
	}
}
