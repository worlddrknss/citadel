package server

import (
	"net/http"
	"testing"
)

// TestCertificatesExposePathLen: CA rows in the list and the detail carry
// isCA and their pathLenConstraint (absent when unlimited).
func TestCertificatesExposePathLen(t *testing.T) {
	e := newPKIEnv(t, nil)
	root := e.createCA("admin", map[string]any{"commonName": "Root", "keyAlgorithm": "EC_prime256v1"})
	sub := e.createCA("admin", map[string]any{"caType": "SUBORDINATE", "commonName": "Sub", "keyAlgorithm": "EC_prime256v1", "parentCaId": root})
	rec := e.do("editor", "POST", "/v1/certificates/issue/generate", map[string]any{"caId": sub, "commonName": "leaf.example.com", "keyAlgorithm": "EC_prime256v1"})
	wantStatus(t, rec, http.StatusOK)

	rec = e.do("viewer", "GET", "/v1/certificates", nil)
	wantStatus(t, rec, http.StatusOK)
	rows := map[string]map[string]any{}
	for _, c := range decode(t, rec)["certificates"].([]any) {
		row := c.(map[string]any)
		rows[row["id"].(string)] = row
	}
	if r := rows[root]; r["isCA"] != true || r["pathLen"] != nil {
		t.Fatalf("root row = %v, want isCA and no pathLen (unlimited)", r)
	}
	if _, present := rows[root]["pathLen"]; present {
		t.Fatal("unlimited root reports a pathLen")
	}
	if r := rows[sub]; r["isCA"] != true || r["pathLen"] != float64(0) {
		t.Fatalf("subordinate row = %v, want pathLen 0", r)
	}
	for id, r := range rows {
		if r["source"] == "pca-cert" {
			if _, ok := r["isCA"]; ok {
				t.Fatalf("leaf %s reports isCA", id)
			}
			if _, ok := r["pathLen"]; ok {
				t.Fatalf("leaf %s reports pathLen", id)
			}
		}
	}

	detail := decode(t, e.do("viewer", "GET", "/v1/certificates/detail?source=pca-ca&id="+sub, nil))
	if detail["isCA"] != true || detail["pathLen"] != float64(0) {
		t.Fatalf("subordinate detail = %v", detail)
	}
	detail = decode(t, e.do("viewer", "GET", "/v1/certificates/detail?source=pca-ca&id="+root, nil))
	if _, ok := detail["pathLen"]; ok || detail["isCA"] != true {
		t.Fatalf("root detail = %v", detail)
	}
}
