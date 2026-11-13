package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// Generated bootstrap tokens (migration 0902). Every replica in bootstrap
// mode offers to issue one at startup; the first wins and logs it, the others
// accept that token because they check presented tokens against this table.

// BootstrapTokenTTL is how long a generated token stays valid. After that the
// next replica to start issues a fresh one (and logs it), so a token whose
// log line was lost doesn't block setup forever.
const BootstrapTokenTTL = 24 * time.Hour

// IssueBootstrapToken stores tokenHash as the deployment's bootstrap token
// unless a valid one (unconsumed and younger than ttl) already exists. It
// reports whether this call issued it; when false, another replica (or an
// earlier start) holds the current token. issuedAt is when the current token
// was created.
func (s *Store) IssueBootstrapToken(ctx context.Context, tokenHash string, ttl time.Duration) (issued bool, issuedAt time.Time, err error) {
	err = s.db.QueryRowContext(ctx, `
INSERT INTO bootstrap_tokens (id, token_hash, created_at) VALUES (1, $1, NOW())
ON CONFLICT (id) DO UPDATE SET token_hash = EXCLUDED.token_hash, created_at = NOW(), consumed_at = NULL
WHERE bootstrap_tokens.consumed_at IS NOT NULL OR bootstrap_tokens.created_at < NOW() - make_interval(secs => $2)
RETURNING created_at`, tokenHash, ttl.Seconds()).Scan(&issuedAt)
	if err == nil {
		return true, issuedAt.UTC(), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, time.Time{}, err
	}
	// Someone else's token is current.
	if err = s.db.QueryRowContext(ctx, `SELECT created_at FROM bootstrap_tokens WHERE id = 1`).Scan(&issuedAt); err != nil {
		return false, time.Time{}, err
	}
	return false, issuedAt.UTC(), nil
}

// BootstrapTokenValid reports whether tokenHash is the current, unconsumed
// and unexpired bootstrap token.
func (s *Store) BootstrapTokenValid(ctx context.Context, tokenHash string, ttl time.Duration) (bool, error) {
	var ok bool
	err := s.db.QueryRowContext(ctx, `
SELECT EXISTS (SELECT 1 FROM bootstrap_tokens
WHERE id = 1 AND token_hash = $1 AND consumed_at IS NULL AND created_at >= NOW() - make_interval(secs => $2))`,
		tokenHash, ttl.Seconds()).Scan(&ok)
	return ok, err
}

// consumeBootstrapToken marks tokenHash used inside the bootstrap
// transaction. Exactly one caller can consume it; the row update also
// serializes with a concurrent consumer.
func consumeBootstrapToken(ctx context.Context, tx *sql.Tx, tokenHash string) error {
	res, err := tx.ExecContext(ctx, `
UPDATE bootstrap_tokens SET consumed_at = NOW()
WHERE id = 1 AND token_hash = $1 AND consumed_at IS NULL AND created_at >= NOW() - make_interval(secs => $2)`,
		tokenHash, BootstrapTokenTTL.Seconds())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return store.ErrBootstrapTokenInvalid
	}
	return nil
}
