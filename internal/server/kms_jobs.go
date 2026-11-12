package server

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// KMS background jobs (on the server job runner): "kms-lifecycle" rotates
// keys whose rotation period has elapsed and destroys keys whose scheduled
// deletion date has passed; "kms-rewrap", registered only when previous
// wrapping keys are configured, re-wraps stored material onto the current
// wrapping key (at start, then daily). Every action is audited with the
// actor kmsJobActor. Runs are idempotent and safe on several replicas: the
// store re-checks each key under a row lock before acting, and re-wrap
// updates are conditional on the ciphertext being unchanged.

const kmsJobActor = "system:kms-scheduler"

// registerKMSJobs registers the KMS jobs with the server's job runner.
func (s *Server) registerKMSJobs() {
	interval := s.cfg.KMSJobInterval
	if interval <= 0 {
		interval = time.Hour
	}
	s.jobs.Every("kms-lifecycle", interval, func(ctx context.Context) error {
		s.runKMSJobsOnce(ctx, time.Now().UTC())
		return nil
	})
	if len(s.cfg.PreviousWrappingKeys) > 0 {
		s.jobs.Every("kms-rewrap", 24*time.Hour, func(ctx context.Context) error {
			_, err := s.runKMSRewrap(ctx, kmsJobOrigin(""))
			return err
		})
	}
}

// runKMSJobsOnce performs one pass: due rotations, then expired deletions.
func (s *Server) runKMSJobsOnce(ctx context.Context, now time.Time) {
	due, err := s.store.ListKeysDueForRotation(ctx, now)
	if err != nil {
		slog.Error("kms job: list keys due for rotation", "err", err)
	}
	for _, ref := range due {
		if ctx.Err() != nil {
			return
		}
		actx := store.WithCallerAccount(ctx, ref.AccountID)
		_, err := s.store.RotateKeyMaterial(actx, ref.KeyID, store.RotationKindAutomatic, now)
		switch {
		case err == nil:
			s.recordAudit(actx, store.AuditEvent{Action: "kms.RotateKey", KeyID: ref.KeyID, Result: "ok", AuditOrigin: kmsJobOrigin(ref.AccountID)})
		case errors.Is(err, store.ErrRotationNotDue):
			// Another replica got there first, or the schedule changed.
		default:
			slog.Error("kms job: rotate key", "key_id", ref.KeyID, "err", err)
			s.recordAudit(actx, store.AuditEvent{Action: "kms.RotateKey", KeyID: ref.KeyID, Result: "error", ErrorType: "InternalError", AuditOrigin: kmsJobOrigin(ref.AccountID)})
		}
	}

	expired, err := s.store.ListKeysPendingDeletion(ctx, now)
	if err != nil {
		slog.Error("kms job: list keys pending deletion", "err", err)
	}
	for _, ref := range expired {
		if ctx.Err() != nil {
			return
		}
		actx := store.WithCallerAccount(ctx, ref.AccountID)
		// Like AWS, deletion proceeds even when secrets or parameters still
		// reference the key; record how many so the loss is traceable.
		errType := ""
		if key, rerr := s.store.ResolveByID(actx, ref.KeyID); rerr == nil {
			if used, uerr := s.store.CountKeyUsage(actx, key); uerr == nil && used.Secrets+used.Parameters > 0 {
				errType = "KeyInUse"
				slog.Warn("kms job: deleting a key that is still referenced", "key_id", ref.KeyID, "secrets", used.Secrets, "parameters", used.Parameters)
			}
		}
		err := s.store.DestroyKey(actx, ref.KeyID)
		switch {
		case err == nil:
			s.recordAudit(actx, store.AuditEvent{Action: "kms.DeleteKey", KeyID: ref.KeyID, Result: "ok", ErrorType: errType, AuditOrigin: kmsJobOrigin(ref.AccountID)})
		case errors.Is(err, store.ErrImmutableManagedKey):
			s.recordAudit(actx, store.AuditEvent{Action: "kms.DeleteKey", KeyID: ref.KeyID, Result: "error", ErrorType: "UnsupportedOperationException", AuditOrigin: kmsJobOrigin(ref.AccountID)})
		default:
			slog.Error("kms job: delete key", "key_id", ref.KeyID, "err", err)
			s.recordAudit(actx, store.AuditEvent{Action: "kms.DeleteKey", KeyID: ref.KeyID, Result: "error", ErrorType: "InternalError", AuditOrigin: kmsJobOrigin(ref.AccountID)})
		}
	}
}

// kmsJobOrigin is the audit origin of background-job actions.
func kmsJobOrigin(accountID string) store.AuditOrigin {
	return store.AuditOrigin{AccountID: accountID, Actor: kmsJobActor, ActorType: store.AuditActorSystem}
}

// runKMSRewrap re-wraps stored material onto the current wrapping key and
// audits the outcome.
func (s *Server) runKMSRewrap(ctx context.Context, origin store.AuditOrigin) (store.RewrapReport, error) {
	report, err := s.store.RewrapAll(ctx)
	result, errType := "ok", ""
	if err != nil {
		slog.Error("kms rewrap failed", "err", err)
		result, errType = "error", "InternalError"
	} else if report.Failed > 0 {
		result, errType = "error", "UnwrapFailed"
	}
	slog.Info("kms rewrap", "scanned", report.Scanned, "rewrapped", report.Rewrapped, "failed", report.Failed, "key_material", report.KeyMaterial, "access_key_secrets", report.AccessKeySecrets, "sts_session_secrets", report.STSSessionSecrets)
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RewrapKeyMaterial", Result: result, ErrorType: errType, AuditOrigin: origin})
	return report, err
}
