//go:build acme_integration

// Package main integration test for the Let's Encrypt (ACME client) issuance
// flow. It exercises the real issueLetsEncryptCertificate path end to end
// against a local Pebble ACME server (Let's Encrypt's official test server) with
// pebble-challtestsrv providing DNS. HTTP-01 validation is served by Citadel's
// own acmeChallengeStore / handleACMEChallengeToken handler.
//
// Requires Docker. Run with:
//
//	go test -tags acme_integration -run TestLetsEncryptIssue93rdAvenue -v ./cmd/server/
//
// It is intentionally excluded from the default build/test run so normal CI is
// unaffected and no public domain or network egress is required.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	itestNetwork   = "gokms-acme-itest-net"
	itestPGName    = "gokms-acme-itest-pg"
	itestCTSName   = "gokms-acme-itest-cts"
	itestPebble    = "gokms-acme-itest-pebble"
	itestChallenge = "5002"
	itestPebbleDir = "https://localhost:14000/dir"
	itestPGPort    = "55432"
	itestDomain    = "93rdavenue.com"
)

func TestLetsEncryptIssue93rdAvenue(t *testing.T) {
	requireDocker(t)

	teardown := func() {
		_ = exec.Command("docker", "rm", "-f", itestPGName, itestCTSName, itestPebble).Run()
		_ = exec.Command("docker", "network", "rm", itestNetwork).Run()
	}
	teardown()
	t.Cleanup(teardown)

	mustRun(t, "docker", "network", "create", itestNetwork)

	hostIP := hostDockerInternalIP(t)
	t.Logf("host address reachable from containers: %s", hostIP)

	// Postgres for a real dbStore (wrapping + settings + storage are exercised).
	mustRun(t, "docker", "run", "-d", "--name", itestPGName, "--network", itestNetwork,
		"-p", itestPGPort+":5432",
		"-e", "POSTGRES_PASSWORD=postgres", "-e", "POSTGRES_DB=kms",
		"postgres:16-alpine")

	// challtestsrv: DNS only, answering every A query with the host IP so Pebble
	// connects back to our challenge server. Its own challenge servers are off.
	mustRun(t, "docker", "run", "-d", "--name", itestCTSName, "--network", itestNetwork,
		"ghcr.io/letsencrypt/pebble-challtestsrv:latest",
		"-defaultIPv4", hostIP, "-defaultIPv6", "",
		"-dnsserver", ":8053", "-doh", "",
		"-http01", "", "-https01", "", "-tlsalpn01", "",
		"-management", ":8055")

	// Pebble ACME server using challtestsrv for DNS resolution. A custom config
	// makes issuance synchronous (retryAfter 0) so the finalize response is
	// immediately "valid"; this avoids relying on Pebble setting a Location
	// header on the finalize response. Against real Let's Encrypt the standard
	// processing+poll path is used.
	pebbleCfg := writePebbleConfig(t)
	mustRun(t, "docker", "run", "-d", "--name", itestPebble, "--network", itestNetwork,
		"-p", "14000:14000", "-e", "PEBBLE_VA_NOSLEEP=1",
		"-v", pebbleCfg+":/test/config/pebble-config.json:ro",
		"ghcr.io/letsencrypt/pebble:latest",
		"-config", "test/config/pebble-config.json",
		"-dnsserver", itestCTSName+":8053")

	caPool := loadPebbleCA(t)
	httpClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caPool}},
	}
	waitForDirectory(t, httpClient, itestPebbleDir)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	db := waitForPostgres(t, "postgres://postgres:postgres@localhost:"+itestPGPort+"/kms?sslmode=disable")
	defer db.Close()
	if err := ensureSchema(ctx, db); err != nil {
		t.Fatalf("ensureSchema: %v", err)
	}
	store := &dbStore{db: db, wrappingKey: bytes.Repeat([]byte{0x42}, 32)}
	if err := putSetting(ctx, db, settingACMELEDirectoryURL, itestPebbleDir); err != nil {
		t.Fatalf("putSetting directory: %v", err)
	}

	s := &server{
		store:          store,
		acmeChallenges: newACMEChallengeStore(),
		acmeHTTPClient: httpClient,
	}

	// Citadel's own HTTP-01 responder, reachable from the Pebble container via
	// the host IP on the challenge port Pebble validates against.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/acme-challenge/{token}", s.handleACMEChallengeToken)
	ln, err := net.Listen("tcp", "0.0.0.0:"+itestChallenge)
	if err != nil {
		t.Fatalf("listen challenge port: %v", err)
	}
	chSrv := &http.Server{Handler: mux}
	go func() { _ = chSrv.Serve(ln) }()
	defer chSrv.Close()

	// Act: issue a publicly-(test-)trusted certificate for 93rdavenue.com.
	cert, err := s.issueLetsEncryptCertificate(ctx, []string{itestDomain})
	if err != nil {
		dumpContainerLogs(t)
		t.Fatalf("issueLetsEncryptCertificate(%s): %v", itestDomain, err)
	}

	// Assert: domains, validity, parseable chain, persisted key.
	if cert.Domains != itestDomain {
		t.Errorf("domains = %q, want %q", cert.Domains, itestDomain)
	}
	if cert.Status != "ISSUED" {
		t.Errorf("status = %q, want ISSUED", cert.Status)
	}
	if !cert.NotAfter.After(time.Now()) {
		t.Errorf("NotAfter = %v, want future", cert.NotAfter)
	}
	leaf := parsePEMCert(t, cert.CertB64)
	if !containsString(leaf.DNSNames, itestDomain) {
		t.Errorf("leaf DNSNames = %v, want to contain %q", leaf.DNSNames, itestDomain)
	}
	chainPEM, _ := base64.StdEncoding.DecodeString(cert.ChainB64)
	if !bytes.Contains(chainPEM, []byte("BEGIN CERTIFICATE")) {
		t.Errorf("chain does not contain a PEM certificate block")
	}
	if len(cert.KeyDER) == 0 {
		t.Errorf("leaf private key was not generated/stored")
	}

	// Assert: round-trips through the store with the key unwrapped.
	stored, err := s.store.GetACMELECertificate(ctx, cert.CertID)
	if err != nil {
		t.Fatalf("GetACMELECertificate: %v", err)
	}
	if len(stored.KeyDER) == 0 {
		t.Errorf("stored certificate key did not unwrap")
	}
	list, err := s.store.ListACMELECertificates(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListACMELECertificates: got %d certs, err=%v", len(list), err)
	}

	t.Logf("issued 93rdavenue.com cert serial=%s notAfter=%s", cert.Serial, cert.NotAfter.Format(time.RFC3339))
}

// writePebbleConfig writes a Pebble config that issues synchronously and returns
// its host path for mounting into the container.
func writePebbleConfig(t *testing.T) string {
	t.Helper()
	const cfg = `{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "test/certs/localhost/cert.pem",
    "privateKey": "test/certs/localhost/key.pem",
    "httpPort": 5002,
    "tlsPort": 5001,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false,
    "retryAfter": { "authz": 0, "order": 0 }
  }
}`
	dir := t.TempDir()
	path := dir + "/pebble-config.json"
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write pebble config: %v", err)
	}
	return path
}

func requireDocker(t *testing.T) {
	t.Helper()
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skipf("docker not available: %v", err)
	}
}

func mustRun(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

// hostDockerInternalIP resolves the address containers use to reach the host.
func hostDockerInternalIP(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("docker", "run", "--rm", "alpine:latest",
		"getent", "hosts", "host.docker.internal").CombinedOutput()
	if err != nil {
		t.Fatalf("resolve host.docker.internal: %v\n%s", err, out)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		t.Fatalf("could not parse host.docker.internal address from %q", out)
	}
	return fields[0]
}

func loadPebbleCA(t *testing.T) *x509.CertPool {
	t.Helper()
	tmp, err := os.CreateTemp("", "pebble-ca-*.pem")
	if err != nil {
		t.Fatalf("temp ca: %v", err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	cid, err := exec.Command("docker", "create", "ghcr.io/letsencrypt/pebble:latest").Output()
	if err != nil {
		t.Fatalf("docker create pebble: %v", err)
	}
	id := strings.TrimSpace(string(cid))
	defer exec.Command("docker", "rm", id).Run()
	if out, err := exec.Command("docker", "cp", id+":/test/certs/pebble.minica.pem", tmp.Name()).CombinedOutput(); err != nil {
		t.Fatalf("extract pebble CA: %v\n%s", err, out)
	}
	pemBytes, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatalf("read pebble CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatalf("failed to load pebble CA into pool")
	}
	return pool
}

func waitForDirectory(t *testing.T, client *http.Client, dirURL string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(dirURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(time.Second)
	}
	dumpContainerLogs(t)
	t.Fatalf("pebble directory %s not ready within timeout", dirURL)
}

func waitForPostgres(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if err := db.Ping(); err == nil {
			return db
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("postgres not ready within timeout")
	return nil
}

func parsePEMCert(t *testing.T, certB64 string) *x509.Certificate {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		t.Fatalf("decode cert b64: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("no PEM block in leaf certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}
	return cert
}

func dumpContainerLogs(t *testing.T) {
	t.Helper()
	for _, name := range []string{itestPebble, itestCTSName} {
		out, _ := exec.Command("docker", "logs", "--tail", "40", name).CombinedOutput()
		t.Logf("--- logs %s ---\n%s", name, out)
	}
	_ = fmt.Sprint
}
