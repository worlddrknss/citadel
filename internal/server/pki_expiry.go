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
// and Let's Encrypt) EXPIRED. Let's Encrypt certificates are not renewed
// automatically: the existing client needs an interactive HTTP-01 or DNS-01
// flow, so the console list reports expiringSoon instead.
func (s *Server) certificateExpiryJob(ctx context.Context) error {
	s.markExpiredCertificates(ctx, time.Now().UTC())
	return nil
}

func (s *Server) markExpiredCertificates(ctx context.Context, now time.Time) int64 {
	n, err := s.store.MarkExpiredCertificates(ctx, now)
	if err != nil {
		log.Printf("certificate expiry job: %v", err)
		return 0
	}
	if n > 0 {
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.MarkCertificatesExpired", Result: "ok",
			AuditOrigin: store.AuditOrigin{Actor: "certificate-expiry-job", ActorType: store.AuditActorSystem, Resource: strconv.FormatInt(n, 10) + " certificates"}})
	}
	return n
}
