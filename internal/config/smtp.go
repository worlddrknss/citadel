package config

import (
	"errors"
	"fmt"
	"net/mail"
	"os"
	"strconv"
	"strings"
)

// SMTP TLS modes. There is deliberately no plaintext mode: credentials and
// notification contents never cross the network unencrypted.
const (
	// SMTPStartTLS connects in plaintext and upgrades with STARTTLS before
	// anything else is sent; a server that doesn't offer STARTTLS is
	// refused.
	SMTPStartTLS = "starttls"
	// SMTPImplicitTLS speaks TLS from the first byte (SMTPS, usually 465).
	SMTPImplicitTLS = "tls"
)

// SMTPConfig is the deployment's outgoing mail server, used by email
// notification channels. Host "" means email notifications are not
// available.
type SMTPConfig struct {
	Host string
	Port int
	// TLS is SMTPStartTLS or SMTPImplicitTLS.
	TLS      string
	Username string
	// Password is KMS_SMTP_PASSWORD; PasswordFile (KMS_SMTP_PASSWORD_FILE)
	// is read on every use instead, so a mounted secret can rotate. Use
	// SMTPPassword to read it.
	Password     string
	PasswordFile string
	// From is the envelope and header sender address.
	From string
}

// Enabled reports whether an SMTP server is configured.
func (c SMTPConfig) Enabled() bool { return c.Host != "" }

// SMTPPassword returns the SMTP password ("" when none is configured).
func (c SMTPConfig) SMTPPassword() (string, error) {
	if c.Password != "" {
		return c.Password, nil
	}
	if c.PasswordFile == "" {
		return "", nil
	}
	b, err := os.ReadFile(c.PasswordFile)
	if err != nil {
		return "", errors.New("the SMTP password file could not be read")
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

// loadSMTPEnv reads KMS_SMTP_*.
func loadSMTPEnv(cfg *Config) error {
	host := strings.TrimSpace(os.Getenv("KMS_SMTP_HOST"))
	if host == "" {
		for _, k := range []string{"KMS_SMTP_PORT", "KMS_SMTP_TLS", "KMS_SMTP_USERNAME", "KMS_SMTP_PASSWORD", "KMS_SMTP_PASSWORD_FILE", "KMS_SMTP_FROM"} {
			if os.Getenv(k) != "" {
				return fmt.Errorf("%s is set but KMS_SMTP_HOST is not", k)
			}
		}
		return nil
	}
	if strings.ContainsAny(host, " /:\r\n") && !strings.HasPrefix(host, "[") {
		return errors.New("KMS_SMTP_HOST must be a host name or address, without a port (use KMS_SMTP_PORT)")
	}
	c := SMTPConfig{Host: strings.Trim(host, "[]")}
	c.TLS = strings.ToLower(strings.TrimSpace(os.Getenv("KMS_SMTP_TLS")))
	port := strings.TrimSpace(os.Getenv("KMS_SMTP_PORT"))
	switch {
	case port != "":
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("KMS_SMTP_PORT must be a port number")
		}
		c.Port = n
	case c.TLS == SMTPImplicitTLS:
		c.Port = 465
	default:
		c.Port = 587
	}
	if c.TLS == "" {
		c.TLS = SMTPStartTLS
		if c.Port == 465 {
			c.TLS = SMTPImplicitTLS
		}
	}
	if c.TLS != SMTPStartTLS && c.TLS != SMTPImplicitTLS {
		return errors.New("KMS_SMTP_TLS must be starttls or tls (plaintext SMTP is not supported)")
	}
	c.Username = os.Getenv("KMS_SMTP_USERNAME")
	c.Password = os.Getenv("KMS_SMTP_PASSWORD")
	c.PasswordFile = strings.TrimSpace(os.Getenv("KMS_SMTP_PASSWORD_FILE"))
	if c.Password != "" && c.PasswordFile != "" {
		return errors.New("set KMS_SMTP_PASSWORD or KMS_SMTP_PASSWORD_FILE, not both")
	}
	if (c.Password != "" || c.PasswordFile != "") && c.Username == "" {
		return errors.New("KMS_SMTP_PASSWORD needs KMS_SMTP_USERNAME")
	}
	from := strings.TrimSpace(os.Getenv("KMS_SMTP_FROM"))
	if from == "" {
		return errors.New("KMS_SMTP_FROM is required when KMS_SMTP_HOST is set")
	}
	addr, err := mail.ParseAddress(from)
	if err != nil || strings.ContainsAny(from, "\r\n") {
		return errors.New("KMS_SMTP_FROM must be an email address, optionally with a display name")
	}
	c.From = addr.String()
	cfg.SMTP = c
	return nil
}
