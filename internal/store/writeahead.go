package store

import (
	"context"
	"time"
)

// WriteAheadStore answers "is there work?" for background sweeps that change
// many rows in one call, so the job writes its write-ahead audit attempt
// only when something is about to change (not on every idle run).
type WriteAheadStore interface {
	// SecretsDueForPurge counts, per account, secrets whose deletion date
	// is at or before now (what PurgeExpiredSecrets would remove).
	SecretsDueForPurge(ctx context.Context, now time.Time) (map[string]int, error)
	// CertificatesDueForExpiry counts what MarkExpiredCertificates would
	// mark EXPIRED (scoped to the caller account when ctx has one).
	CertificatesDueForExpiry(ctx context.Context, now time.Time) (int64, error)
}
