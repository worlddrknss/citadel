package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/config"
	"github.com/worlddrknss/citadel/internal/store/memory"
	"github.com/worlddrknss/citadel/internal/store/postgres"
)

// TestSharedLoginLimitAcrossReplicas: sign-in attempts for one user spread
// over two replicas are limited together, not per replica.
func TestSharedLoginLimitAcrossReplicas(t *testing.T) {
	stA := pgTestStore(t)
	stB := replicaOn(t, stA)
	override := map[string]sharedLimit{"login-user": {"login-user", 3, time.Minute}}
	mk := func(st *postgres.Store) http.Handler {
		s := &Server{cfg: config.Config{SessionIdleTTL: time.Hour, SessionAbsTTL: time.Hour}, store: st, sharedLimitOverrides: override}
		s.auth().bootstrapped.Store(true)
		return s.Handler()
	}
	replicas := []http.Handler{mk(stA), mk(stB)}
	body := map[string]string{"accountId": "123456789012", "username": "Mallory", "password": "guess-guess-guess"}
	var codes []int
	for i := 0; i < 4; i++ {
		rec := doReq(t, replicas[i%2], "POST", "/v1/login", body, nil)
		codes = append(codes, rec.Code)
		if rec.Code == http.StatusTooManyRequests && rec.Header().Get("Retry-After") == "" {
			t.Fatal("429 without Retry-After")
		}
	}
	// Each replica saw two attempts, under its local burst; the shared
	// limit of 3 refuses the fourth.
	if codes[0] != http.StatusUnauthorized || codes[2] != http.StatusUnauthorized || codes[3] != http.StatusTooManyRequests {
		t.Fatalf("codes = %v, want 401 401 401 429", codes)
	}
	// The username is matched without case.
	body["username"] = "mallory"
	if rec := doReq(t, replicas[0], "POST", "/v1/login", body, nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("lower-case username = %d", rec.Code)
	}
}

// TestSharedAllowTokenLimits checks both workload token counters in one call
// and that limits are per key.
func TestSharedAllowTokenLimits(t *testing.T) {
	st := pgTestStore(t)
	s := &Server{store: st, sharedLimitOverrides: map[string]sharedLimit{
		"wi-token-ip":     {"wi-token-ip", 100, time.Minute},
		"wi-token-client": {"wi-token-client", 2, time.Minute},
	}}
	ctx := context.Background()
	check := func(client string) bool {
		ok, _ := s.sharedAllow(ctx, sharedLimitCheck{sharedLimitTokenIP, "198.51.100.1"}, sharedLimitCheck{sharedLimitTokenClient, client})
		return ok
	}
	if !check("wic-a") || !check("wic-a") {
		t.Fatal("within the limit refused")
	}
	if check("wic-a") {
		t.Fatal("third request for the client allowed")
	}
	if !check("wic-b") {
		t.Fatal("another client is limited by the first one's counter")
	}
	ok, wait := s.sharedAllow(ctx, sharedLimitCheck{sharedLimitTokenClient, "wic-a"})
	if ok || wait <= 0 || wait > time.Minute {
		t.Fatalf("refusal = %v, wait %v", ok, wait)
	}
	if err := s.purgeSharedLimitsJob(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestSharedAllowFailsOpen: a database error doesn't lock everyone out (the
// local buckets still apply), and the memory store has no shared counters.
func TestSharedAllowFailsOpen(t *testing.T) {
	st := pgTestStore(t)
	if _, err := st.DB().Exec(`DROP TABLE rate_limit_counters`); err != nil {
		t.Fatal(err)
	}
	s := &Server{store: st, sharedLimitOverrides: map[string]sharedLimit{"login-ip": {"login-ip", 0, time.Minute}}}
	if ok, _ := s.sharedAllow(context.Background(), sharedLimitCheck{sharedLimitLoginIP, "x"}); !ok {
		t.Fatal("database error refused the request")
	}
	mem := &Server{store: &memory.Store{DefaultKey: sampleKey(1)}}
	if ok, _ := mem.sharedAllow(context.Background(), sharedLimitCheck{sharedLimitLoginIP, "x"}); !ok {
		t.Fatal("memory store refused")
	}
}
