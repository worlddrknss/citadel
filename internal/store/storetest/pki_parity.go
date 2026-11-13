package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// RunPKIParity runs the PKIParityStore contract tests: ACM idempotency
// claims and the pending subordinate CA lifecycle.
func RunPKIParity(t *testing.T, env PKIEnv) {
	st := env.Store
	ctxA := store.WithCallerAccount(context.Background(), acctA)
	ctxB := store.WithCallerAccount(context.Background(), acctB)
	now := time.Now().UTC().Truncate(time.Second)

	t.Run("IdempotencyTokens", func(t *testing.T) {
		rec := store.ACMIdempotencyRecord{Operation: "RequestCertificate", Token: "tok1", ParamsHash: "h1", ARN: "arn:acm/1", CreatedAt: now}
		got, claimed, err := st.ClaimACMIdempotencyToken(ctxA, rec, now.Add(-time.Hour))
		must(t, err)
		if !claimed || got.ARN != "arn:acm/1" {
			t.Fatalf("first claim = %+v, %v", got, claimed)
		}
		again := rec
		again.ARN, again.ParamsHash = "arn:acm/2", "h2"
		got, claimed, err = st.ClaimACMIdempotencyToken(ctxA, again, now.Add(-time.Hour))
		must(t, err)
		if claimed || got.ARN != "arn:acm/1" || got.ParamsHash != "h1" {
			t.Fatalf("second claim = %+v, %v", got, claimed)
		}
		// Another operation and another tenant are separate namespaces.
		other := again
		other.Operation = "ImportCertificate"
		if _, claimed, err = st.ClaimACMIdempotencyToken(ctxA, other, now.Add(-time.Hour)); err != nil || !claimed {
			t.Fatalf("other operation claim: %v, %v", claimed, err)
		}
		if _, claimed, err = st.ClaimACMIdempotencyToken(ctxB, again, now.Add(-time.Hour)); err != nil || !claimed {
			t.Fatalf("other tenant claim: %v, %v", claimed, err)
		}
		// Past the window the token is free again.
		later := again
		later.CreatedAt = now.Add(2 * time.Hour)
		got, claimed, err = st.ClaimACMIdempotencyToken(ctxA, later, now.Add(time.Hour))
		must(t, err)
		if !claimed || got.ARN != "arn:acm/2" {
			t.Fatalf("expired claim = %+v, %v", got, claimed)
		}
		// Release only removes the claim naming the ARN.
		must(t, st.ReleaseACMIdempotencyToken(ctxA, "RequestCertificate", "tok1", "arn:acm/1"))
		if got, claimed, _ = st.ClaimACMIdempotencyToken(ctxA, rec, now.Add(time.Hour)); claimed || got.ARN != "arn:acm/2" {
			t.Fatalf("release of a stale ARN removed the claim: %+v %v", got, claimed)
		}
		must(t, st.ReleaseACMIdempotencyToken(ctxA, "RequestCertificate", "tok1", "arn:acm/2"))
		if _, claimed, _ = st.ClaimACMIdempotencyToken(ctxA, later, now.Add(time.Hour)); !claimed {
			t.Fatal("released token could not be claimed")
		}
	})

	t.Run("PendingCA", func(t *testing.T) {
		pending := store.PCACertificateAuthority{CAID: "ca-pending-" + acctA, ARN: "arn:ca/pending-a", Type: "SUBORDINATE", KMSKeyID: env.NewCAKey(ctxA),
			SubjectDN: "CN=Pending", State: store.CAStatePendingCertificate, CreatedAt: now, UpdatedAt: now}
		must(t, st.CreateCertificateAuthority(ctxA, pending))
		must(t, st.PutCertificateAuthorityCSR(ctxA, pending.CAID, "Y3Ny"))
		csr, err := st.GetCertificateAuthorityCSR(ctxA, pending.CAID)
		must(t, err)
		if csr != "Y3Ny" {
			t.Fatalf("csr = %q", csr)
		}
		if _, err := st.GetCertificateAuthorityCSR(ctxB, pending.CAID); !errors.Is(err, store.ErrCANotFound) {
			t.Fatalf("other tenant read CSR: %v", err)
		}
		if err := st.PutCertificateAuthorityCSR(ctxB, pending.CAID, "eA=="); !errors.Is(err, store.ErrCANotFound) {
			t.Fatalf("other tenant wrote CSR: %v", err)
		}
		pl := 0
		act := pending
		act.CACertB64, act.SubjectDN, act.PathLength, act.ParentCAID = "Y2VydA==", "CN=Pending,O=X", &pl, "parent-1"
		act.NotBefore, act.NotAfter = now, now.Add(time.Hour)
		if err := st.ActivateCertificateAuthority(ctxB, act); !errors.Is(err, store.ErrCANotFound) {
			t.Fatalf("other tenant activated: %v", err)
		}
		must(t, st.ActivateCertificateAuthority(ctxA, act))
		got, err := st.GetCertificateAuthorityByID(ctxA, pending.CAID)
		must(t, err)
		if got.State != "ACTIVE" || got.CACertB64 != "Y2VydA==" || got.ParentCAID != "parent-1" || got.PathLength == nil || *got.PathLength != 0 ||
			!got.NotAfter.Equal(act.NotAfter) || got.SubjectDN != "CN=Pending,O=X" {
			t.Fatalf("activated CA = %+v", got)
		}
		if err := st.ActivateCertificateAuthority(ctxA, act); !errors.Is(err, store.ErrCANotPending) {
			t.Fatalf("second activation: %v", err)
		}
		if err := st.ActivateCertificateAuthority(ctxA, store.PCACertificateAuthority{CAID: "missing"}); !errors.Is(err, store.ErrCANotFound) {
			t.Fatalf("activate missing: %v", err)
		}
	})
}
