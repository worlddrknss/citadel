package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// RunPKILifecycle runs the CA deletion / restore and certificate removal
// contract tests.
func RunPKILifecycle(t *testing.T, env PKIEnv) {
	st := env.Store
	ctxA := store.WithCallerAccount(context.Background(), acctA)
	ctxB := store.WithCallerAccount(context.Background(), acctB)
	now := time.Now().UTC().Truncate(time.Second)

	root := store.PCACertificateAuthority{CAID: "lc-root", ARN: "arn:ca/lc-root", Type: "ROOT", KMSKeyID: env.NewCAKey(ctxA),
		SubjectDN: "CN=LC Root", State: "ACTIVE", NotBefore: now, NotAfter: now.Add(24 * time.Hour), CreatedAt: now, UpdatedAt: now}
	sub := store.PCACertificateAuthority{CAID: "lc-sub", ARN: "arn:ca/lc-sub", Type: "SUBORDINATE", KMSKeyID: env.NewCAKey(ctxA),
		SubjectDN: "CN=LC Sub", State: "ACTIVE", ParentCAID: root.CAID, NotBefore: now, NotAfter: now.Add(24 * time.Hour), CreatedAt: now, UpdatedAt: now}
	must(t, st.CreateCertificateAuthority(ctxA, root))
	must(t, st.CreateCertificateAuthority(ctxA, sub))
	cert := func(id, serial string, notAfter time.Time) store.PCACertificate {
		return store.PCACertificate{CertID: id, CAID: sub.CAID, Serial: serial, CertB64: "AA==", Status: "ISSUED",
			NotBefore: now.Add(-48 * time.Hour), NotAfter: notAfter, Template: "EndEntityCertificate/V1", CreatedAt: now, UpdatedAt: now}
	}
	must(t, st.CreateCertificate(ctxA, cert("lc-live", "1", now.Add(time.Hour))))
	must(t, st.CreateCertificate(ctxA, cert("lc-expired", "2", now.Add(-time.Hour))))
	must(t, st.CreateCertificate(ctxA, cert("lc-revoked", "3", now.Add(time.Hour))))
	must(t, st.RevokeCertificate(ctxA, "lc-revoked", "KeyCompromise"))

	t.Run("OutstandingCertificates", func(t *testing.T) {
		n, err := st.CountOutstandingCertificates(ctxA, sub.CAID, now)
		must(t, err)
		if n != 1 {
			t.Fatalf("sub outstanding = %d, want 1 (live only)", n)
		}
		// The root's outstanding issuance is the live subordinate CA.
		if n, err = st.CountOutstandingCertificates(ctxA, root.CAID, now); err != nil || n != 1 {
			t.Fatalf("root outstanding = %d %v", n, err)
		}
		if _, err := st.CountOutstandingCertificates(ctxB, sub.CAID, now); !errors.Is(err, store.ErrCANotFound) {
			t.Fatalf("other account: %v", err)
		}
	})

	t.Run("HideCertificate", func(t *testing.T) {
		must(t, st.HideCertificate(ctxA, "lc-expired", now))
		if err := st.HideCertificate(ctxA, "lc-expired", now); !errors.Is(err, store.ErrCertificateNotFound) {
			t.Fatalf("hide twice: %v", err)
		}
		if err := st.HideCertificate(ctxB, "lc-live", now); !errors.Is(err, store.ErrCertificateNotFound) {
			t.Fatalf("hide other account's: %v", err)
		}
		// The row stays readable (for the CRL) with DeletedAt set.
		c, err := st.GetCertificate(ctxA, "lc-expired")
		must(t, err)
		if c.DeletedAt == nil {
			t.Fatal("DeletedAt not set")
		}
		list, err := st.ListCertificates(ctxA, sub.CAID)
		must(t, err)
		if len(list) != 3 {
			t.Fatalf("list = %d rows", len(list))
		}
	})

	t.Run("DeleteRestorePurge", func(t *testing.T) {
		until := now.Add(7 * 24 * time.Hour)
		if _, err := st.TransitionCertificateAuthority(ctxA, sub.CAID, []string{store.CAStateDisabled}, store.CAStateDeleted, &until); !errors.Is(err, store.ErrCAStateConflict) {
			t.Fatalf("delete an active CA: %v", err)
		}
		if _, err := st.TransitionCertificateAuthority(ctxB, sub.CAID, []string{store.CAStateActive}, store.CAStateDisabled, nil); !errors.Is(err, store.ErrCANotFound) {
			t.Fatalf("other account: %v", err)
		}
		ca, err := st.TransitionCertificateAuthority(ctxA, sub.CAID, []string{store.CAStateActive}, store.CAStateDisabled, nil)
		must(t, err)
		if ca.State != store.CAStateDisabled || ca.RestorableUntil != nil {
			t.Fatalf("disabled = %+v", ca)
		}
		ca, err = st.TransitionCertificateAuthority(ctxA, sub.CAID, []string{store.CAStateDisabled}, store.CAStateDeleted, &until)
		must(t, err)
		if ca.State != store.CAStateDeleted || ca.RestorableUntil == nil || !ca.RestorableUntil.Equal(until) {
			t.Fatalf("deleted = %+v", ca)
		}
		got, err := st.GetCertificateAuthorityByID(ctxA, sub.CAID)
		must(t, err)
		if got.RestorableUntil == nil || !got.RestorableUntil.Equal(until) {
			t.Fatalf("read back = %+v", got)
		}
		// A deleted subordinate no longer counts against its parent.
		if n, _ := st.CountOutstandingCertificates(ctxA, root.CAID, now); n != 0 {
			t.Fatalf("root outstanding after sub deletion = %d", n)
		}
		if due, err := st.ListCertificateAuthoritiesDueForPurge(context.Background(), now); err != nil || len(due) != 0 {
			t.Fatalf("due before the window ends = %+v %v", due, err)
		}
		if ok, err := st.PurgeCertificateAuthority(context.Background(), sub.CAID, now); err != nil || ok {
			t.Fatalf("purge before the window ends = %v %v", ok, err)
		}

		// Restore goes to DISABLED and clears the window.
		ca, err = st.TransitionCertificateAuthority(ctxA, sub.CAID, []string{store.CAStateDeleted}, store.CAStateDisabled, nil)
		must(t, err)
		if ca.State != store.CAStateDisabled || ca.RestorableUntil != nil {
			t.Fatalf("restored = %+v", ca)
		}

		// Delete again and let the window pass.
		_, err = st.TransitionCertificateAuthority(ctxA, sub.CAID, []string{store.CAStateDisabled}, store.CAStateDeleted, &until)
		must(t, err)
		later := until.Add(time.Second)
		due, err := st.ListCertificateAuthoritiesDueForPurge(context.Background(), later)
		must(t, err)
		if len(due) != 1 || due[0].CAID != sub.CAID || due[0].AccountID != acctA {
			t.Fatalf("due = %+v", due)
		}
		ok, err := st.PurgeCertificateAuthority(context.Background(), sub.CAID, later)
		must(t, err)
		if !ok {
			t.Fatal("purge did not run")
		}
		if ok, _ := st.PurgeCertificateAuthority(context.Background(), sub.CAID, later); ok {
			t.Fatal("purged twice")
		}
		if _, err := st.GetCertificateAuthorityByID(ctxA, sub.CAID); !errors.Is(err, store.ErrCANotFound) {
			t.Fatalf("purged CA still readable: %v", err)
		}
		if _, err := st.GetCertificate(ctxA, "lc-live"); !errors.Is(err, store.ErrCertificateNotFound) {
			t.Fatalf("purged CA's certificate still readable: %v", err)
		}
	})
}

// RunLERenewal runs the Let's Encrypt renewal-state contract tests (for
// backends that store Let's Encrypt certificates).
func RunLERenewal(t *testing.T, st store.Store) {
	ctxA := store.WithCallerAccount(context.Background(), acctA)
	ctxB := store.WithCallerAccount(context.Background(), acctB)
	now := time.Now().UTC().Truncate(time.Second)
	mk := func(id, kind string, auto bool, notAfter time.Time) {
		must(t, st.CreateACMELECertificate(ctxA, store.ACMELECertificate{CertID: id, DirectoryURL: "https://acme.test/dir", Domains: id + ".example.com",
			Serial: "1", CertB64: "AA==", KeyDER: []byte{1, 2, 3}, Status: "ISSUED", NotBefore: now.Add(-60 * 24 * time.Hour), NotAfter: notAfter,
			ChallengeKind: kind, AutoRenew: auto}))
	}
	mk("le-due", store.ACMELEOrderHTTP01, true, now.Add(10*24*time.Hour))
	mk("le-later", store.ACMELEOrderHTTP01, true, now.Add(60*24*time.Hour))
	mk("le-dns", store.ACMELEOrderDNS01, false, now.Add(5*24*time.Hour))

	c, err := st.GetACMELECertificate(ctxA, "le-due")
	must(t, err)
	if c.ChallengeKind != store.ACMELEOrderHTTP01 || !c.AutoRenew || c.AccountID != acctA || c.RenewNextAttemptAt != nil {
		t.Fatalf("get = %+v", c)
	}
	window := now.Add(30 * 24 * time.Hour)
	due, err := st.ListACMELERenewalsDue(context.Background(), window, now, 10)
	must(t, err)
	if len(due) != 1 || due[0].CertID != "le-due" || due[0].AccountID != acctA {
		t.Fatalf("due = %+v", due)
	}
	if due, _ := st.ListACMELERenewalsDue(ctxB, window, now, 10); len(due) != 0 {
		t.Fatalf("other account sees due renewals: %+v", due)
	}

	// One claim wins; the lease hides it from the due list.
	lease := now.Add(10 * time.Minute)
	if ok, err := st.ClaimACMELERenewal(context.Background(), "le-due", now, lease); err != nil || !ok {
		t.Fatalf("claim = %v %v", ok, err)
	}
	if ok, _ := st.ClaimACMELERenewal(context.Background(), "le-due", now, lease); ok {
		t.Fatal("claimed twice")
	}
	if due, _ := st.ListACMELERenewalsDue(context.Background(), window, now, 10); len(due) != 0 {
		t.Fatalf("leased renewal still due: %+v", due)
	}

	// A failure counts an attempt and schedules the next one.
	next := now.Add(time.Hour)
	must(t, st.RecordACMELERenewal(context.Background(), "le-due", store.ACMELERenewalResult{At: now, Error: "validation failed", NextAttemptAt: next}))
	c, err = st.GetACMELECertificate(ctxA, "le-due")
	must(t, err)
	if c.RenewAttempts != 1 || c.RenewLastError != "validation failed" || c.RenewNextAttemptAt == nil || !c.RenewNextAttemptAt.Equal(next) ||
		c.RenewLastAttemptAt == nil || !c.RenewLastAttemptAt.Equal(now) {
		t.Fatalf("after failure = %+v", c)
	}
	if due, _ := st.ListACMELERenewalsDue(context.Background(), window, next, 10); len(due) != 1 {
		t.Fatalf("not due again after the backoff: %+v", due)
	}

	// Turning auto-renew off and on resets the backoff.
	must(t, st.SetACMELEAutoRenew(ctxA, "le-due", false))
	if due, _ := st.ListACMELERenewalsDue(context.Background(), window, next, 10); len(due) != 0 {
		t.Fatalf("auto-renew off but due: %+v", due)
	}
	must(t, st.SetACMELEAutoRenew(ctxA, "le-due", true))
	c, _ = st.GetACMELECertificate(ctxA, "le-due")
	if !c.AutoRenew || c.RenewAttempts != 0 || c.RenewNextAttemptAt != nil {
		t.Fatalf("after re-enable = %+v", c)
	}
	if err := st.SetACMELEAutoRenew(ctxB, "le-due", false); !errors.Is(err, store.ErrCertificateNotFound) {
		t.Fatalf("other account toggles: %v", err)
	}

	// Success records the replacement and stops renewals of this one.
	must(t, st.RecordACMELERenewal(context.Background(), "le-due", store.ACMELERenewalResult{At: now, NewCertID: "le-new"}))
	c, _ = st.GetACMELECertificate(ctxA, "le-due")
	if c.RenewedBy != "le-new" || c.RenewAttempts != 0 || c.RenewLastError != "" || c.RenewNextAttemptAt != nil {
		t.Fatalf("after success = %+v", c)
	}
	if due, _ := st.ListACMELERenewalsDue(context.Background(), window, next, 10); len(due) != 0 {
		t.Fatalf("renewed certificate still due: %+v", due)
	}
	list, err := st.ListACMELECertificates(ctxA)
	must(t, err)
	if len(list) != 3 {
		t.Fatalf("list = %+v", list)
	}

	if err := st.DeleteACMELECertificate(ctxB, "le-dns"); !errors.Is(err, store.ErrCertificateNotFound) {
		t.Fatalf("other account deletes: %v", err)
	}
	must(t, st.DeleteACMELECertificate(ctxA, "le-dns"))
	if err := st.DeleteACMELECertificate(ctxA, "le-dns"); !errors.Is(err, store.ErrCertificateNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}
