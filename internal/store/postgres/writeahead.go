package postgres

import (
	"context"
	"fmt"
	"time"
)

// SecretsDueForPurge implements store.WriteAheadStore.
func (s *Store) SecretsDueForPurge(ctx context.Context, now time.Time) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT account_id, COUNT(*) FROM sm_secrets WHERE deleted_date IS NOT NULL AND deleted_date <= $1 GROUP BY account_id`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var acct string
		var n int
		if err := rows.Scan(&acct, &n); err != nil {
			return nil, err
		}
		out[acct] = n
	}
	return out, rows.Err()
}

// CertificatesDueForExpiry implements store.WriteAheadStore, mirroring
// MarkExpiredCertificates.
func (s *Store) CertificatesDueForExpiry(ctx context.Context, now time.Time) (int64, error) {
	var total int64
	stmts := []string{
		`SELECT COUNT(*) FROM pca_certificates WHERE status = 'ISSUED' AND not_after < $1`,
		`SELECT COUNT(*) FROM acm_certificates WHERE status = 'ISSUED' AND not_after < $1`,
		`SELECT COUNT(*) FROM acme_le_certificates WHERE status = 'ISSUED' AND not_after < $1`,
		`SELECT COUNT(*) FROM pca_certificate_authorities WHERE state = 'ACTIVE' AND not_after < $1`,
	}
	for _, q := range stmts {
		cond, args := andAccount(ctx, "account_id", 2)
		var n int64
		if err := s.db.QueryRowContext(ctx, q+cond, append([]any{now}, args...)...).Scan(&n); err != nil {
			return total, fmt.Errorf("count expired: %w", err)
		}
		total += n
	}
	return total, nil
}
