package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store/postgres"
)

// ---- first-run bootstrap token ---------------------------------------------
//
// Setup needs a one-time token: KMS_BOOTSTRAP_TOKEN when set, otherwise one
// Citadel generates. With PostgreSQL the generated token is shared: every
// replica offers to issue one at startup, the first to store its SHA-256
// wins and logs the token, and the others log that a token was already
// issued. Any replica accepts it (checked against the database), and the
// bootstrap transaction consumes it, so it works exactly once. With the
// memory store (one process) the token stays in memory.

// bootstrapTokenHelp is the 401 message for a missing, wrong or used token.
const bootstrapTokenHelp = "the bootstrap token is missing, wrong or already used; it is printed in the log of the first Citadel replica to start (or set KMS_BOOTSTRAP_TOKEN)"

// bootstrapTokenStore is implemented by stores that share generated bootstrap
// tokens between replicas (*postgres.Store).
type bootstrapTokenStore interface {
	IssueBootstrapToken(ctx context.Context, tokenHash string, ttl time.Duration) (bool, time.Time, error)
	BootstrapTokenValid(ctx context.Context, tokenHash string, ttl time.Duration) (bool, error)
}

func hashBootstrapToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// sharedBootstrapTokens returns the store's shared token support, unless
// KMS_BOOTSTRAP_TOKEN is set (then the configured token is used as is).
func (s *Server) sharedBootstrapTokens() (bootstrapTokenStore, bool) {
	if s.cfg.BootstrapToken != "" {
		return nil, false
	}
	bs, ok := s.store.(bootstrapTokenStore)
	return bs, ok
}

// initBootstrapToken readies the one-time bootstrap token when setup is
// required and returns the token this process holds in memory: the
// configured one, a generated one for the memory store, or the one this
// replica issued to the database ("" when another replica issued it).
func (s *Server) initBootstrapToken() string {
	st := s.identity()
	st.bootMu.Lock()
	defer st.bootMu.Unlock()
	if st.bootToken != "" || st.bootConsumed || st.bootShared {
		return st.bootToken
	}
	if s.cfg.BootstrapToken != "" {
		st.bootToken = s.cfg.BootstrapToken
		slog.Info("bootstrap setup requires the token from KMS_BOOTSTRAP_TOKEN")
		return st.bootToken
	}
	tok := cryptoutil.RandomHex(16)
	if bs, ok := s.sharedBootstrapTokens(); ok {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		issued, at, err := bs.IssueBootstrapToken(ctx, hashBootstrapToken(tok), postgres.BootstrapTokenTTL)
		switch {
		case err != nil:
			// The database check will fail too; keep a token this replica
			// accepts so setup is still possible here.
			slog.Error("bootstrap token: could not store it in the database; this token works only on this replica", "error", err)
			slog.Warn("bootstrap token (one-time, needed to complete first-run setup)", "bootstrapToken", tok)
			st.bootToken = tok
		case issued:
			st.bootShared = true
			st.bootToken = tok
			slog.Warn("bootstrap token (one-time, needed to complete first-run setup; accepted by every replica)",
				"bootstrapToken", tok, "validUntil", at.Add(postgres.BootstrapTokenTTL).Format(time.RFC3339))
		default:
			st.bootShared = true
			slog.Info("bootstrap token already issued by another replica (or an earlier start of this one); "+
				"find it in the log of the replica that started first, or set KMS_BOOTSTRAP_TOKEN",
				"issuedAt", at.Format(time.RFC3339), "validUntil", at.Add(postgres.BootstrapTokenTTL).Format(time.RFC3339))
		}
		return st.bootToken
	}
	st.bootToken = tok
	slog.Warn("bootstrap token (one-time, needed to complete first-run setup)", "bootstrapToken", st.bootToken)
	return st.bootToken
}

// checkBootstrapToken reports whether presented is the bootstrap token. For
// a token shared through the database it also returns the hash the
// bootstrap transaction must consume.
func (s *Server) checkBootstrapToken(ctx context.Context, presented string) (ok bool, sharedHash string) {
	local := s.initBootstrapToken()
	presented = strings.TrimSpace(presented)
	if presented == "" {
		return false, ""
	}
	st := s.identity()
	st.bootMu.Lock()
	shared, consumed := st.bootShared, st.bootConsumed
	st.bootMu.Unlock()
	if consumed {
		return false, ""
	}
	if shared {
		bs, _ := s.sharedBootstrapTokens()
		h := hashBootstrapToken(presented)
		valid, err := bs.BootstrapTokenValid(ctx, h, postgres.BootstrapTokenTTL)
		if err != nil {
			slog.Error("bootstrap token: check", "error", err)
			return false, ""
		}
		return valid, h
	}
	if local == "" {
		return false, ""
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(local)) == 1, ""
}

// consumeBootstrapToken invalidates the in-memory token after setup (the
// shared one was consumed in the bootstrap transaction).
func (s *Server) consumeBootstrapToken() {
	st := s.identity()
	st.bootMu.Lock()
	st.bootToken, st.bootConsumed = "", true
	st.bootMu.Unlock()
}
