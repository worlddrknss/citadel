package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/config"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/postgres"
)

// replicaOn opens a second store on st's database, as another replica would.
func replicaOn(t *testing.T, st *postgres.Store) *postgres.Store {
	t.Helper()
	r, err := postgres.Open(context.Background(), st.DB(), postgres.Options{
		WrappingKey: bytes.Repeat([]byte{0x42}, 32), AuditHMACKey: bytes.Repeat([]byte{0x24}, 32),
		Region: "us-west-2", AccountID: "123456789012",
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func bootstrapServer(st store.Store) *Server {
	return &Server{cfg: config.Config{SessionIdleTTL: 30 * time.Minute, SessionAbsTTL: 12 * time.Hour}, store: st}
}

// TestBootstrapTokenSharedAcrossReplicas: the first replica issues and logs
// the token, the second learns one exists, and the second accepts the first
// one's token, once.
func TestBootstrapTokenSharedAcrossReplicas(t *testing.T) {
	stA := pgTestStore(t)
	stB := replicaOn(t, stA)
	a, b := bootstrapServer(stA), bootstrapServer(stB)

	tok := a.initBootstrapToken()
	if len(tok) != 32 {
		t.Fatalf("first replica token = %q", tok)
	}
	if got := b.initBootstrapToken(); got != "" {
		t.Fatalf("second replica generated its own token %q", got)
	}
	ctx := context.Background()
	if ok, hash := b.checkBootstrapToken(ctx, tok); !ok || hash != hashBootstrapToken(tok) {
		t.Fatalf("second replica rejects the first replica's token (%v, %q)", ok, hash)
	}
	if ok, _ := b.checkBootstrapToken(ctx, tok+"x"); ok {
		t.Fatal("wrong token accepted")
	}

	body := map[string]string{"organizationName": "Acme", "accountName": "Production", "username": "founder", "password": "a-long-password-1", "bootstrapToken": tok}
	wantStatus(t, doReq(t, b.Handler(), "POST", "/v1/bootstrap", body, nil), http.StatusCreated)
	// Consumed: the token is no longer valid anywhere.
	if ok, _ := a.checkBootstrapToken(ctx, tok); ok {
		t.Fatal("token still valid on the first replica after setup")
	}
	var consumed bool
	if err := stA.DB().QueryRow(`SELECT consumed_at IS NOT NULL FROM bootstrap_tokens`).Scan(&consumed); err != nil || !consumed {
		t.Fatalf("token row consumed = %v, %v", consumed, err)
	}
}

// TestBootstrapTokenConsumedOnce: concurrent setups with the same token
// (on different replicas) create exactly one admin.
func TestBootstrapTokenConsumedOnce(t *testing.T) {
	stA := pgTestStore(t)
	stB := replicaOn(t, stA)
	ctx := context.Background()
	hash := hashBootstrapToken("concurrent-token")
	if issued, _, err := stA.IssueBootstrapToken(ctx, hash, postgres.BootstrapTokenTTL); err != nil || !issued {
		t.Fatalf("issue = %v, %v", issued, err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, st := range []*postgres.Store{stA, stB} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = st.Bootstrap(ctx, store.BootstrapRequest{
				OrganizationName: "Acme", AccountName: "Prod", Username: "founder", PasswordHash: "x", BootstrapTokenHash: hash,
			})
		}()
	}
	wg.Wait()
	okCount := 0
	for _, err := range errs {
		switch {
		case err == nil:
			okCount++
		case errors.Is(err, store.ErrAlreadyBootstrapped), errors.Is(err, store.ErrBootstrapTokenInvalid):
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if okCount != 1 {
		t.Fatalf("%d setups succeeded, want 1 (%v)", okCount, errs)
	}
	// A wrong hash never bootstraps.
	if _, err := stA.Bootstrap(ctx, store.BootstrapRequest{AccountName: "Other", Username: "x", PasswordHash: "x", BootstrapTokenHash: "nope"}); err == nil {
		t.Fatal("bootstrap with a wrong token hash succeeded")
	}
}

// TestBootstrapTokenReissuedAfterExpiry: an expired, unused token is replaced
// by the next replica to start, so a lost log line doesn't block setup.
func TestBootstrapTokenReissuedAfterExpiry(t *testing.T) {
	st := pgTestStore(t)
	ctx := context.Background()
	if issued, _, _ := st.IssueBootstrapToken(ctx, "h1", time.Hour); !issued {
		t.Fatal("first issue")
	}
	if issued, _, _ := st.IssueBootstrapToken(ctx, "h2", time.Hour); issued {
		t.Fatal("a valid token was replaced")
	}
	if _, err := st.DB().Exec(`UPDATE bootstrap_tokens SET created_at = NOW() - INTERVAL '2 hours'`); err != nil {
		t.Fatal(err)
	}
	if ok, _ := st.BootstrapTokenValid(ctx, "h1", time.Hour); ok {
		t.Fatal("expired token still valid")
	}
	if issued, _, _ := st.IssueBootstrapToken(ctx, "h3", time.Hour); !issued {
		t.Fatal("expired token not replaced")
	}
	if ok, _ := st.BootstrapTokenValid(ctx, "h3", time.Hour); !ok {
		t.Fatal("new token not valid")
	}
}
