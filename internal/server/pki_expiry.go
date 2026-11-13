package server

import (
	"context"
	"log"
	"strconv"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// certificateExpiryInterval is how often the expiry job runs.
const certificateExpiryInterval = time.Hour

// certificateExpiryJob marks expired certificates and CAs (private CA, ACM
// and Let's Encrypt) EXPIRED. HTTP-01 Let's Encrypt certificates are renewed
// by the letsencrypt-renew job (le_autorenew.go); DNS-01 ones need the
// operator, and the console list reports expiringSoon for them.
func (s *Server) certificateExpiryJob(ctx context.Context) error {
	s.markExpiredCertificates(ctx, time.Now().UTC())
	return nil
}

func (s *Server) markExpiredCertificates(ctx context.Context, now time.Time) int64 {
	origin := store.AuditOrigin{Actor: "certificate-expiry-job", ActorType: store.AuditActorSystem}
	due, err := s.store.CertificatesDueForExpiry(ctx, now)
	if err != nil || due == 0 {
		if err != nil {
			log.Printf("certificate expiry job: %v", err)
		}
		return 0
	}
	origin.Resource = strconv.FormatInt(due, 10) + " certificates"
	ctx, err = s.beginJobAudit(ctx, store.AuditEvent{Action: "citadel.MarkCertificatesExpired", AuditOrigin: origin})
	if err != nil {
		log.Printf("certificate expiry job: skipped this run, the audit log is unavailable")
		return 0
	}
	n, err := s.store.MarkExpiredCertificates(ctx, now)
	if err != nil {
		log.Printf("certificate expiry job: %v", err)
		s.finishAudit(ctx, store.AuditResultError, "InternalError")
		return 0
	}
	if n == 0 {
		s.finishAudit(ctx, store.AuditResultSuccess, "")
	}
	if n > 0 {
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.MarkCertificatesExpired", Result: "ok",
			AuditOrigin: store.AuditOrigin{Actor: "certificate-expiry-job", ActorType: store.AuditActorSystem, Resource: strconv.FormatInt(n, 10) + " certificates"}})
	}
	return n
}
