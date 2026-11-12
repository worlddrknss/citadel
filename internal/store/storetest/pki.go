// Package storetest holds behavioural tests shared by every store.Store
// backend, so the in-memory and PostgreSQL stores are held to the same
// contract.
package storetest

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// acctA and acctB are shared with the secrets suite (secrets_ext.go).

// PKIEnv is what the PKI suite needs from a backend.
type PKIEnv struct {
	Store store.Store
	// NewCAKey returns a KMS key ID a CA record may reference.
	NewCAKey func(ctx context.Context) string
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// RunPKI runs the PKI store contract tests.
func RunPKI(t *testing.T, env PKIEnv) {
	st := env.Store
	ctxA := store.WithCallerAccount(context.Background(), acctA)
	ctxB := store.WithCallerAccount(context.Background(), acctB)
	now := time.Now().UTC().Truncate(time.Second)

	t.Run("CertificateAuthorities", func(t *testing.T) {
		pl := 0
		root := store.PCACertificateAuthority{CAID: "ca-root-" + acctA, ARN: "arn:ca/root-a", Type: "ROOT", KMSKeyID: env.NewCAKey(ctxA),
			SubjectDN: "CN=Root A", State: "ACTIVE", NotBefore: now, NotAfter: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now}
		sub := store.PCACertificateAuthority{CAID: "ca-sub-" + acctA, ARN: "arn:ca/sub-a", Type: "SUBORDINATE", KMSKeyID: env.NewCAKey(ctxA),
			SubjectDN: "CN=Sub A", State: "ACTIVE", PathLength: &pl, ParentCAID: root.CAID,
			NotBefore: now, NotAfter: now.Add(time.Hour), CreatedAt: now.Add(time.Second), UpdatedAt: now}
		must(t, st.CreateCertificateAuthority(ctxA, root))
		must(t, st.CreateCertificateAuthority(ctxA, sub))

		got, err := st.GetCertificateAuthorityByID(ctxA, sub.CAID)
		must(t, err)
		if got.ParentCAID != root.CAID || got.PathLength == nil || *got.PathLength != 0 || got.AccountID != acctA {
			t.Fatalf("sub CA = %+v", got)
		}
		if _, err := st.DescribeCertificateAuthority(ctxA, root.ARN); err != nil {
			t.Fatalf("describe own CA: %v", err)
		}
		if _, err := st.DescribeCertificateAuthority(ctxB, root.ARN); !errors.Is(err, store.ErrCANotFound) {
			t.Fatalf("describe other tenant's CA: %v", err)
		}
		if _, err := st.GetCertificateAuthorityByID(ctxB, root.CAID); !errors.Is(err, store.ErrCANotFound) {
			t.Fatalf("get other tenant's CA: %v", err)
		}
		list, err := st.ListCertificateAuthorities(ctxA)
		must(t, err)
		if len(list) != 2 || list[0].CAID != sub.CAID {
			t.Fatalf("list A = %+v", list)
		}
		list, err = st.ListCertificateAuthorities(ctxB)
		must(t, err)
		if len(list) != 0 {
			t.Fatalf("list B = %+v", list)
		}
	})

	t.Run("Certificates", func(t *testing.T) {
		ca := store.PCACertificateAuthority{CAID: "ca-certs", ARN: "arn:ca/certs", Type: "ROOT", KMSKeyID: env.NewCAKey(ctxA),
			SubjectDN: "CN=Certs", State: "ACTIVE", NotBefore: now, NotAfter: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now}
		must(t, st.CreateCertificateAuthority(ctxA, ca))
		c1 := store.PCACertificate{CertID: "cert-1", CAID: ca.CAID, Serial: "1001", CertB64: "AA==", Status: "ISSUED",
			NotBefore: now, NotAfter: now.Add(time.Hour), Template: "EndEntityServerAuthCertificate/V1", CreatedAt: now, UpdatedAt: now}
		c2 := c1
		c2.CertID, c2.Serial, c2.CreatedAt = "cert-2", "1002", now.Add(time.Second)
		must(t, st.CreateCertificate(ctxA, c1))
		must(t, st.CreateCertificate(ctxA, c2))

		got, err := st.GetCertificate(ctxA, "cert-1")
		must(t, err)
		if got.AccountID != acctA || got.Template != c1.Template {
			t.Fatalf("cert = %+v", got)
		}
		if _, err := st.GetCertificate(ctxB, "cert-1"); !errors.Is(err, store.ErrCertificateNotFound) {
			t.Fatalf("other tenant get: %v", err)
		}
		list, err := st.ListCertificates(ctxA, ca.CAID)
		must(t, err)
		if len(list) != 2 || list[0].CertID != "cert-2" {
			t.Fatalf("list = %+v", list)
		}
		if list, _ := st.ListCertificates(ctxB, ca.CAID); len(list) != 0 {
			t.Fatalf("other tenant list = %+v", list)
		}
		found, err := st.FindCertificatesBySerial(context.Background(), "1002")
		must(t, err)
		if len(found) != 1 || found[0].CertID != "cert-2" {
			t.Fatalf("by serial = %+v", found)
		}
		if found, _ := st.FindCertificatesBySerial(ctxB, "1002"); len(found) != 0 {
			t.Fatalf("other tenant by serial = %+v", found)
		}

		if err := st.RevokeCertificate(ctxB, "cert-1", "KeyCompromise"); !errors.Is(err, store.ErrCertificateNotFound) {
			t.Fatalf("other tenant revoke: %v", err)
		}
		must(t, st.RevokeCertificate(ctxA, "cert-1", "KeyCompromise"))
		if err := st.RevokeCertificate(ctxA, "cert-1", "KeyCompromise"); !errors.Is(err, store.ErrCertificateAlreadyRevoked) {
			t.Fatalf("second revoke: %v", err)
		}
		got, _ = st.GetCertificate(ctxA, "cert-1")
		if got.Status != "REVOKED" || got.RevokedAt == nil || got.RevocationReason != "KeyCompromise" {
			t.Fatalf("revoked cert = %+v", got)
		}
	})

	t.Run("MarkExpired", func(t *testing.T) {
		ca := store.PCACertificateAuthority{CAID: "ca-exp", ARN: "arn:ca/exp", Type: "ROOT", KMSKeyID: env.NewCAKey(ctxB),
			SubjectDN: "CN=Exp", State: "ACTIVE", NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now}
		must(t, st.CreateCertificateAuthority(ctxB, ca))
		old := store.PCACertificate{CertID: "cert-old", CAID: ca.CAID, Serial: "2001", Status: "ISSUED",
			NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour), CreatedAt: now, UpdatedAt: now}
		fresh := old
		fresh.CertID, fresh.Serial, fresh.NotAfter = "cert-fresh", "2002", now.Add(time.Hour)
		must(t, st.CreateCertificate(ctxB, old))
		must(t, st.CreateCertificate(ctxB, fresh))
		// Another tenant's job run sees nothing of B's.
		n, err := st.MarkExpiredCertificates(ctxA, now)
		must(t, err)
		if c, _ := st.GetCertificate(ctxB, "cert-old"); c.Status != "ISSUED" {
			t.Fatalf("tenant A's run expired B's cert (n=%d)", n)
		}
		n, err = st.MarkExpiredCertificates(context.Background(), now)
		must(t, err)
		if n < 1 {
			t.Fatalf("expired %d rows", n)
		}
		if c, _ := st.GetCertificate(ctxB, "cert-old"); c.Status != "EXPIRED" {
			t.Fatalf("old cert status %s", c.Status)
		}
		if c, _ := st.GetCertificate(ctxB, "cert-fresh"); c.Status != "ISSUED" {
			t.Fatalf("fresh cert status %s", c.Status)
		}
	})

	t.Run("ACMEServerSettings", func(t *testing.T) {
		if _, err := st.GetACMEServerSettings(ctxA); !errors.Is(err, store.ErrACMEServerSettingsNotFound) {
			t.Fatalf("missing settings: %v", err)
		}
		in := store.ACMEServerSettings{IssuingCAID: "ca-1", AllowedDomains: []string{"a.example"}, ValidationAllowedCIDRs: []string{"127.0.0.0/8"}, UpdatedBy: "alice"}
		must(t, st.PutACMEServerSettings(ctxA, in))
		got, err := st.GetACMEServerSettings(ctxA)
		must(t, err)
		if got.AccountID != acctA || got.IssuingCAID != "ca-1" || len(got.AllowedDomains) != 1 || got.AllowedIPRanges == nil || len(got.ValidationAllowedCIDRs) != 1 || got.UpdatedBy != "alice" {
			t.Fatalf("settings = %+v", got)
		}
		in.IssuingCAID = "ca-2"
		must(t, st.PutACMEServerSettings(ctxA, in))
		if got, _ := st.GetACMEServerSettings(ctxA); got.IssuingCAID != "ca-2" {
			t.Fatalf("updated settings = %+v", got)
		}
		if _, err := st.GetACMEServerSettings(ctxB); !errors.Is(err, store.ErrACMEServerSettingsNotFound) {
			t.Fatalf("other tenant settings: %v", err)
		}
	})

	t.Run("EABKeys", func(t *testing.T) {
		secret := bytes.Repeat([]byte{7}, 32)
		must(t, st.CreateEABKey(ctxA, store.EABKey{KID: "kid-a1", Label: "ci", HMACKey: secret, CreatedAt: now, CreatedBy: "alice"}))
		must(t, st.CreateEABKey(ctxA, store.EABKey{KID: "kid-a2", Label: "ci2", HMACKey: secret, CreatedAt: now.Add(time.Second), CreatedBy: "alice"}))
		list, err := st.ListEABKeys(ctxA)
		must(t, err)
		if len(list) != 2 || list[0].KID != "kid-a2" || list[0].HMACKey != nil || list[0].Status != store.EABStatusUnused {
			t.Fatalf("list = %+v", list)
		}
		if list, _ := st.ListEABKeys(ctxB); len(list) != 0 {
			t.Fatalf("other tenant list = %+v", list)
		}
		// The ACME resolver looks keys up without a tenant.
		k, err := st.GetEABKey(context.Background(), "kid-a1")
		must(t, err)
		if !bytes.Equal(k.HMACKey, secret) || k.AccountID != acctA || k.CreatedBy != "alice" {
			t.Fatalf("get = %+v", k)
		}
		if _, err := st.GetEABKey(ctxB, "kid-a1"); !errors.Is(err, store.ErrEABKeyNotFound) {
			t.Fatalf("other tenant get: %v", err)
		}
		must(t, st.BindEABKey(context.Background(), "kid-a1", "acme-acct-1", now))
		if err := st.BindEABKey(context.Background(), "kid-a1", "acme-acct-2", now); !errors.Is(err, store.ErrEABKeyUnavailable) {
			t.Fatalf("second bind: %v", err)
		}
		k, _ = st.GetEABKey(ctxA, "kid-a1")
		if k.Status != store.EABStatusBound || k.ACMEAccountID != "acme-acct-1" || k.BoundAt == nil {
			t.Fatalf("bound key = %+v", k)
		}
		if _, err := st.RevokeEABKey(ctxB, "kid-a2"); !errors.Is(err, store.ErrEABKeyNotFound) {
			t.Fatalf("other tenant revoke: %v", err)
		}
		rk, err := st.RevokeEABKey(ctxA, "kid-a2")
		must(t, err)
		if rk.Status != store.EABStatusRevoked || rk.HMACKey != nil {
			t.Fatalf("revoked = %+v", rk)
		}
		if err := st.BindEABKey(context.Background(), "kid-a2", "acme-acct-3", now); !errors.Is(err, store.ErrEABKeyUnavailable) {
			t.Fatalf("bind revoked: %v", err)
		}
		if err := st.BindEABKey(context.Background(), "kid-missing", "x", now); !errors.Is(err, store.ErrEABKeyUnavailable) {
			t.Fatalf("bind missing: %v", err)
		}
	})

	t.Run("ACMCertificates", func(t *testing.T) {
		key := []byte("pkcs8-key-bytes")
		c := store.ACMCertificate{ARN: "arn:acm/cert-1", Type: store.ACMTypePrivate, CAID: "ca-1", PCACertID: "pca-1",
			DomainName: "a.example", SANs: []string{"a.example", "b.example"}, Serial: "01", CertB64: "AA==", ChainPEM: "chain",
			KeyDER: key, Status: "ISSUED", NotBefore: now, NotAfter: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now}
		must(t, st.CreateACMCertificate(ctxA, c))
		if err := st.CreateACMCertificate(ctxA, c); !errors.Is(err, store.ErrACMCertificateExists) {
			t.Fatalf("duplicate create: %v", err)
		}
		got, err := st.GetACMCertificate(ctxA, c.ARN)
		must(t, err)
		if !bytes.Equal(got.KeyDER, key) || len(got.SANs) != 2 || got.AccountID != acctA || got.ChainPEM != "chain" {
			t.Fatalf("get = %+v", got)
		}
		if _, err := st.GetACMCertificate(ctxB, c.ARN); !errors.Is(err, store.ErrACMCertificateNotFound) {
			t.Fatalf("other tenant get: %v", err)
		}
		list, err := st.ListACMCertificates(ctxA)
		must(t, err)
		if len(list) != 1 || list[0].KeyDER != nil {
			t.Fatalf("list = %+v", list)
		}
		if list, _ := st.ListACMCertificates(ctxB); len(list) != 0 {
			t.Fatalf("other tenant list = %+v", list)
		}
		got.Serial, got.Status = "02", "ISSUED"
		must(t, st.UpdateACMCertificate(ctxA, got))
		if err := st.UpdateACMCertificate(ctxB, got); !errors.Is(err, store.ErrACMCertificateNotFound) {
			t.Fatalf("other tenant update: %v", err)
		}
		got, _ = st.GetACMCertificate(ctxA, c.ARN)
		if got.Serial != "02" || !bytes.Equal(got.KeyDER, key) {
			t.Fatalf("updated = %+v", got)
		}
		if err := st.DeleteACMCertificate(ctxB, c.ARN); !errors.Is(err, store.ErrACMCertificateNotFound) {
			t.Fatalf("other tenant delete: %v", err)
		}
		must(t, st.DeleteACMCertificate(ctxA, c.ARN))
		if _, err := st.GetACMCertificate(ctxA, c.ARN); !errors.Is(err, store.ErrACMCertificateNotFound) {
			t.Fatalf("get deleted: %v", err)
		}
	})
}
