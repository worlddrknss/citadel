package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/acme"
)

// RunACMEStore runs the acme.Store contract tests against st.
func RunACMEStore(t *testing.T, st acme.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	t.Run("Nonces", func(t *testing.T) {
		must(t, st.AddNonce(ctx, "n1", now.Add(time.Hour)))
		must(t, st.AddNonce(ctx, "n2", now.Add(-time.Minute)))
		if ok, err := st.ConsumeNonce(ctx, "n1", now); err != nil || !ok {
			t.Fatalf("consume n1 = %v %v", ok, err)
		}
		if ok, _ := st.ConsumeNonce(ctx, "n1", now); ok {
			t.Fatal("nonce consumed twice")
		}
		if ok, _ := st.ConsumeNonce(ctx, "n2", now); ok {
			t.Fatal("expired nonce accepted")
		}
		if ok, _ := st.ConsumeNonce(ctx, "nope", now); ok {
			t.Fatal("unknown nonce accepted")
		}
	})

	t.Run("NonceConsumedOnce", func(t *testing.T) {
		must(t, st.AddNonce(ctx, "race", now.Add(time.Hour)))
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if ok, err := st.ConsumeNonce(ctx, "race", now); err == nil && ok {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("nonce consumed %d times", wins)
		}
	})

	t.Run("Accounts", func(t *testing.T) {
		a := &acme.Account{ID: "acct-1", Status: acme.StatusValid, Contact: []string{"mailto:a@example.com"},
			KeyJWK: []byte(`{"kty":"EC"}`), KeyThumbprint: "thumb-1", AccountRef: "111111111111", EABKeyID: "kid-1", CreatedAt: now}
		must(t, st.CreateAccount(ctx, a))
		if a.Version != 1 {
			t.Fatalf("version after create = %d", a.Version)
		}
		dup := *a
		dup.ID = "acct-dup"
		if err := st.CreateAccount(ctx, &dup); !errors.Is(err, acme.ErrDuplicate) {
			t.Fatalf("duplicate thumbprint: %v", err)
		}
		got, err := st.GetAccountByThumbprint(ctx, "thumb-1")
		must(t, err)
		if got.ID != "acct-1" || got.AccountRef != "111111111111" || got.EABKeyID != "kid-1" || string(got.KeyJWK) != `{"kty":"EC"}` || got.Version != 1 {
			t.Fatalf("by thumbprint = %+v", got)
		}
		if _, err := st.GetAccount(ctx, "missing"); !errors.Is(err, acme.ErrNotFound) {
			t.Fatalf("missing account: %v", err)
		}

		got.Contact = []string{"mailto:b@example.com"}
		must(t, st.UpdateAccount(ctx, got))
		if got.Version != 2 {
			t.Fatalf("version after update = %d", got.Version)
		}
		stale := *got
		stale.Version = 1
		if err := st.UpdateAccount(ctx, &stale); !errors.Is(err, acme.ErrStale) {
			t.Fatalf("stale update: %v", err)
		}
		missing := *got
		missing.ID = "missing"
		if err := st.UpdateAccount(ctx, &missing); !errors.Is(err, acme.ErrNotFound) {
			t.Fatalf("update missing: %v", err)
		}

		other := &acme.Account{ID: "acct-2", Status: acme.StatusValid, KeyJWK: []byte(`{}`), KeyThumbprint: "thumb-2", CreatedAt: now}
		must(t, st.CreateAccount(ctx, other))
		// Key rollover onto another account's key is a duplicate.
		got.KeyThumbprint = "thumb-2"
		if err := st.UpdateAccount(ctx, got); !errors.Is(err, acme.ErrDuplicate) {
			t.Fatalf("rollover onto taken key: %v", err)
		}
		got, _ = st.GetAccount(ctx, "acct-1")
		got.KeyThumbprint = "thumb-3"
		must(t, st.UpdateAccount(ctx, got))
		if _, err := st.GetAccountByThumbprint(ctx, "thumb-1"); !errors.Is(err, acme.ErrNotFound) {
			t.Fatalf("old thumbprint still indexed: %v", err)
		}
		if g, err := st.GetAccountByThumbprint(ctx, "thumb-3"); err != nil || g.ID != "acct-1" {
			t.Fatalf("new thumbprint = %+v %v", g, err)
		}
	})

	t.Run("OrdersAndAuthorizations", func(t *testing.T) {
		id := acme.Identifier{Type: acme.IdentifierDNS, Value: "www.example.com"}
		az := &acme.Authorization{ID: "az-1", AccountID: "acct-1", Identifier: id, Status: acme.StatusPending, Expires: now.Add(time.Hour),
			Challenges: []acme.Challenge{{ID: "ch-1", Type: acme.ChallengeHTTP01, Token: "tok", Status: acme.StatusPending}}}
		o1 := &acme.Order{ID: "o-1", AccountID: "acct-1", Status: acme.StatusPending, Identifiers: []acme.Identifier{id},
			AuthzIDs: []string{"az-1"}, Expires: now.Add(time.Hour), CreatedAt: now}
		must(t, st.CreateOrder(ctx, o1, []*acme.Authorization{az}))
		if o1.Version != 1 || az.Version != 1 {
			t.Fatalf("versions after create: order %d authz %d", o1.Version, az.Version)
		}
		o2 := &acme.Order{ID: "o-2", AccountID: "acct-1", Status: acme.StatusReady, Expires: now.Add(time.Hour), CreatedAt: now}
		must(t, st.CreateOrder(ctx, o2, nil))
		o3 := &acme.Order{ID: "o-3", AccountID: "acct-1", Status: acme.StatusPending, Expires: now.Add(-time.Minute), CreatedAt: now}
		must(t, st.CreateOrder(ctx, o3, nil))
		// A duplicate authorization ID rejects the whole order.
		if err := st.CreateOrder(ctx, &acme.Order{ID: "o-4", AccountID: "acct-1", Status: acme.StatusPending, Expires: now}, []*acme.Authorization{{ID: "az-1", AccountID: "acct-1", Identifier: id, Expires: now}}); !errors.Is(err, acme.ErrDuplicate) {
			t.Fatalf("duplicate authz: %v", err)
		}
		if _, err := st.GetOrder(ctx, "o-4"); !errors.Is(err, acme.ErrNotFound) {
			t.Fatalf("order of failed create exists: %v", err)
		}

		ids, err := st.ListOrderIDs(ctx, "acct-1")
		must(t, err)
		if len(ids) != 3 || ids[0] != "o-1" || ids[2] != "o-3" {
			t.Fatalf("order ids = %v", ids)
		}
		n, err := st.CountPendingOrders(ctx, "acct-1", now)
		must(t, err)
		if n != 2 {
			t.Fatalf("pending orders = %d", n)
		}

		o, err := st.GetOrder(ctx, "o-1")
		must(t, err)
		o.Status = acme.StatusInvalid
		o.Error = &acme.Problem{Type: "urn:ietf:params:acme:error:unauthorized", Detail: "nope", Status: 403}
		must(t, st.UpdateOrder(ctx, o))
		o.Version = 1
		if err := st.UpdateOrder(ctx, o); !errors.Is(err, acme.ErrStale) {
			t.Fatalf("stale order update: %v", err)
		}
		o, _ = st.GetOrder(ctx, "o-1")
		if o.Error == nil || o.Error.Status != 403 || o.Version != 2 || len(o.AuthzIDs) != 1 {
			t.Fatalf("order = %+v", o)
		}

		if _, err := st.FindValidAuthorization(ctx, "acct-1", id, now); !errors.Is(err, acme.ErrNotFound) {
			t.Fatalf("pending authz found as valid: %v", err)
		}
		a, err := st.GetAuthorization(ctx, "az-1")
		must(t, err)
		a.Status = acme.StatusValid
		a.Challenges[0].Status = acme.StatusValid
		a.Challenges[0].Validated = now
		must(t, st.UpdateAuthorization(ctx, a))
		stale := *a
		stale.Version = 1
		if err := st.UpdateAuthorization(ctx, &stale); !errors.Is(err, acme.ErrStale) {
			t.Fatalf("stale authz update: %v", err)
		}
		v, err := st.FindValidAuthorization(ctx, "acct-1", id, now)
		must(t, err)
		if v.ID != "az-1" || !v.Challenges[0].Validated.Equal(now) {
			t.Fatalf("valid authz = %+v", v)
		}
		if _, err := st.FindValidAuthorization(ctx, "acct-2", id, now); !errors.Is(err, acme.ErrNotFound) {
			t.Fatalf("other account's authz found: %v", err)
		}
		if _, err := st.FindValidAuthorization(ctx, "acct-1", id, now.Add(2*time.Hour)); !errors.Is(err, acme.ErrNotFound) {
			t.Fatalf("expired authz found: %v", err)
		}
	})

	t.Run("Certificates", func(t *testing.T) {
		c := &acme.Certificate{ID: "c-1", AccountID: "acct-1", OrderID: "o-1", Serial: "abc", ChainPEM: []byte("pem"), LeafDER: []byte{1, 2}, NotAfter: now}
		must(t, st.CreateCertificate(ctx, c))
		dup := *c
		dup.ID = "c-2"
		if err := st.CreateCertificate(ctx, &dup); !errors.Is(err, acme.ErrDuplicate) {
			t.Fatalf("duplicate serial: %v", err)
		}
		got, err := st.GetCertificateBySerial(ctx, "abc")
		must(t, err)
		if got.ID != "c-1" || string(got.ChainPEM) != "pem" || len(got.LeafDER) != 2 {
			t.Fatalf("by serial = %+v", got)
		}
		got.Revoked, got.RevocationReason = true, 1
		must(t, st.UpdateCertificate(ctx, got))
		got.Version = 1
		if err := st.UpdateCertificate(ctx, got); !errors.Is(err, acme.ErrStale) {
			t.Fatalf("stale cert update: %v", err)
		}
		got, _ = st.GetCertificate(ctx, "c-1")
		if !got.Revoked || got.RevocationReason != 1 {
			t.Fatalf("cert = %+v", got)
		}
		if _, err := st.GetCertificate(ctx, "missing"); !errors.Is(err, acme.ErrNotFound) {
			t.Fatalf("missing cert: %v", err)
		}
	})
}
