package server

import (
	"context"
	"log"
	"strconv"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// Secrets background jobs.
//
// Purge: a secret scheduled for deletion (DeleteSecret with a recovery
// window) used to linger forever after its deletion date. The purge job
// permanently deletes, in every account, secrets whose deletion date has
// passed, and audits each one as secretsmanager.PurgeSecret with the system
// actor. It runs on the server job runner at startup and then hourly; running it on several
// replicas at once is safe (each delete is re-checked under a row lock).
// Parameters have no deletion schedule (deletes are immediate), so there is
// nothing to purge for them. KMS key deletion is not handled here.
//
// Rotation: built-in rotators run from their own job (see rotation.go).
// Schedules with a Lambda ARN are recorded only: once their date passes the
// console shows the secret as "rotation due" for an operator to rotate.

// secretsPurgeInterval is how often the purge job (registered with s.jobs in
// New) runs; the job runner also runs it once at startup.
const secretsPurgeInterval = time.Hour

// purgeExpiredSecretsJob is the s.jobs entry point.
func (s *Server) purgeExpiredSecretsJob(ctx context.Context) error {
	s.purgeExpiredSecrets(ctx, time.Now().UTC())
	return nil
}

// purgeExpiredSecrets runs one purge round and returns how many secrets it
// removed.
func (s *Server) purgeExpiredSecrets(ctx context.Context, now time.Time) int {
	// Write-ahead: one attempt per account with secrets due, before the
	// purge. If any attempt cannot be written, nothing is purged this run.
	due, err := s.store.SecretsDueForPurge(ctx, now)
	if err != nil {
		log.Printf("secrets purge: %v", err)
		return 0
	}
	if len(due) == 0 {
		return 0
	}
	scopes := make(map[string]context.Context, len(due))
	for acct, n := range due {
		actx, aerr := s.beginJobAudit(store.WithCallerAccount(ctx, acct), store.AuditEvent{
			Action: "secretsmanager.PurgeSecret",
			AuditOrigin: store.AuditOrigin{Actor: "system:secrets-purge", ActorType: store.AuditActorSystem,
				Resource: strconv.Itoa(n) + " secret(s) past their deletion date"},
		})
		if aerr != nil {
			log.Printf("secrets purge: skipped this run, the audit log is unavailable")
			for _, c := range scopes {
				s.finishAudit(c, store.AuditResultError, "AuditUnavailable")
			}
			return 0
		}
		scopes[acct] = actx
	}
	purged, err := s.store.PurgeExpiredSecrets(ctx, now)
	if err != nil {
		log.Printf("secrets purge: %v (purged %d before the error)", err, len(purged))
	}
	for _, p := range purged {
		actx, ok := scopes[p.AccountID]
		if !ok {
			actx = store.WithCallerAccount(ctx, p.AccountID)
		}
		s.recordAudit(actx, store.AuditEvent{
			Action: "secretsmanager.PurgeSecret",
			KeyID:  p.KMSKeyID,
			Result: "ok",
			AuditOrigin: store.AuditOrigin{
				Actor:     "system:secrets-purge",
				ActorType: store.AuditActorSystem,
				Resource:  p.Name,
			},
		})
	}
	for _, c := range scopes {
		s.finishAudit(c, store.AuditResultSuccess, "") // accounts whose secrets were restored meanwhile
	}
	if len(purged) > 0 {
		log.Printf("secrets purge: permanently deleted %d secret(s) past their deletion date", len(purged))
	}
	return len(purged)
}
