package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadIdentityEnv(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KMS_BOOTSTRAP_TOKEN", "short")
	var cfg Config
	if err := loadIdentityEnv(&cfg); err == nil {
		t.Fatal("short bootstrap token accepted")
	}
	t.Setenv("KMS_BOOTSTRAP_TOKEN", "a-long-enough-bootstrap-token")
	file := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(file, []byte(" first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KMS_WORKLOAD_K8S_REVIEWER_TOKEN_FILE", file)
	cfg = Config{}
	if err := loadIdentityEnv(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.BootstrapToken != "a-long-enough-bootstrap-token" || !cfg.K8sReviewConfigured() {
		t.Fatalf("cfg = %+v", cfg)
	}
	if tok, err := cfg.K8sReviewerToken(); err != nil || tok != "first" {
		t.Fatalf("token = %q, %v", tok, err)
	}
	if err := os.WriteFile(file, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	if tok, _ := cfg.K8sReviewerToken(); tok != "second" {
		t.Fatalf("rotated token not reread: %q", tok)
	}
	t.Setenv("KMS_WORKLOAD_K8S_REVIEWER_TOKEN", "static")
	if err := loadIdentityEnv(&Config{}); err == nil {
		t.Fatal("both token sources accepted")
	}
	t.Setenv("KMS_WORKLOAD_K8S_REVIEWER_TOKEN", "")
	t.Setenv("KMS_WORKLOAD_K8S_REVIEWER_TOKEN_FILE", "")
	cfg = Config{}
	if err := loadIdentityEnv(&cfg); err != nil || cfg.K8sReviewConfigured() {
		t.Fatalf("unconfigured = %+v, %v", cfg, err)
	}
}
