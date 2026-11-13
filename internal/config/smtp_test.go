package config

import (
	"os"
	"path/filepath"
	"testing"
)

func clearSMTPEnv(t *testing.T) {
	for _, k := range []string{"KMS_SMTP_HOST", "KMS_SMTP_PORT", "KMS_SMTP_TLS", "KMS_SMTP_USERNAME", "KMS_SMTP_PASSWORD", "KMS_SMTP_PASSWORD_FILE", "KMS_SMTP_FROM"} {
		t.Setenv(k, "")
	}
}

func TestLoadSMTPEnv(t *testing.T) {
	clearSMTPEnv(t)
	var cfg Config
	if err := loadSMTPEnv(&cfg); err != nil || cfg.SMTP.Enabled() {
		t.Fatalf("unset: %+v, %v", cfg.SMTP, err)
	}
	t.Setenv("KMS_SMTP_FROM", "citadel@example.com")
	if err := loadSMTPEnv(&Config{}); err == nil {
		t.Fatal("KMS_SMTP_FROM without a host accepted")
	}

	t.Setenv("KMS_SMTP_HOST", "smtp.example.com")
	t.Setenv("KMS_SMTP_FROM", "Citadel <citadel@example.com>")
	cfg = Config{}
	if err := loadSMTPEnv(&cfg); err != nil {
		t.Fatal(err)
	}
	if c := cfg.SMTP; c.Host != "smtp.example.com" || c.Port != 587 || c.TLS != SMTPStartTLS || c.From != `"Citadel" <citadel@example.com>` {
		t.Fatalf("defaults = %+v", c)
	}

	t.Setenv("KMS_SMTP_PORT", "465")
	cfg = Config{}
	if err := loadSMTPEnv(&cfg); err != nil || cfg.SMTP.TLS != SMTPImplicitTLS {
		t.Fatalf("port 465 = %+v, %v", cfg.SMTP, err)
	}
	t.Setenv("KMS_SMTP_PORT", "")
	t.Setenv("KMS_SMTP_TLS", "tls")
	cfg = Config{}
	if err := loadSMTPEnv(&cfg); err != nil || cfg.SMTP.Port != 465 {
		t.Fatalf("implicit TLS default port = %+v, %v", cfg.SMTP, err)
	}

	for name, env := range map[string][2]string{
		"plaintext":       {"KMS_SMTP_TLS", "none"},
		"bad port":        {"KMS_SMTP_PORT", "99999"},
		"host with port":  {"KMS_SMTP_HOST", "smtp.example.com:25"},
		"bad from":        {"KMS_SMTP_FROM", "not an address"},
		"header in from":  {"KMS_SMTP_FROM", "a@example.com\r\nBcc: x@example.com"},
		"password, no id": {"KMS_SMTP_PASSWORD", "hunter2-hunter2"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(env[0], env[1])
			if err := loadSMTPEnv(&Config{}); err == nil {
				t.Fatalf("%s=%q accepted", env[0], env[1])
			}
		})
	}

	file := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(file, []byte("first-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KMS_SMTP_USERNAME", "citadel")
	t.Setenv("KMS_SMTP_PASSWORD_FILE", file)
	cfg = Config{}
	if err := loadSMTPEnv(&cfg); err != nil {
		t.Fatal(err)
	}
	if pw, err := cfg.SMTP.SMTPPassword(); err != nil || pw != "first-password" {
		t.Fatalf("password = %q, %v", pw, err)
	}
	if err := os.WriteFile(file, []byte("second-password"), 0o600); err != nil {
		t.Fatal(err)
	}
	if pw, _ := cfg.SMTP.SMTPPassword(); pw != "second-password" {
		t.Fatalf("rotated password not reread: %q", pw)
	}
	t.Setenv("KMS_SMTP_PASSWORD", "inline-password")
	if err := loadSMTPEnv(&Config{}); err == nil {
		t.Fatal("both password sources accepted")
	}
}
