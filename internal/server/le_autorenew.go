package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// Let's Encrypt automatic renewal.
//
// HTTP-01 certificates renew unattended: Citadel serves the challenge at
// /.well-known/acme-challenge/ on its public URL, so the "letsencrypt-renew"
// job can run the same order flow as a console request (acme_le_async.go)
// 30 days before a certificate expires. DNS-01 certificates need new TXT
// records each time, so they are marked for manual renewal.
//
// Each certificate carries an autoRenew flag (on by default for HTTP-01),
// toggled with POST /v1/certificates/letsencrypt/auto-renew. The job leases
// a due certificate (so one replica renews it), runs the order (visible in
// the orders API like any other), and on success records the replacement;
// the old certificate stays listed until it expires. A failure is recorded
// with its error, retried with exponential backoff (1 h doubling to 24 h),
// and audited as citadel.LetsEncryptAutoRenewFailed (result error) so it can
// raise an alert.

const (
	leRenewWindow     = 30 * 24 * time.Hour
	leRenewInterval   = time.Hour
	leRenewBatch      = 20
	leRenewBackoffMin = time.Hour
	leRenewBackoffMax = 24 * time.Hour
	leRenewActor      = "letsencrypt-renew-job"
)

// leRenewLease is how long a claimed renewal is hidden from other replicas:
// the order timeout plus room to record the outcome.
var leRenewLease = acmeOrderTimeout + 5*time.Minute

// leRenewalJSON is a Let's Encrypt certificate's renewal state for the console.
type leRenewalJSON struct {
	// Kind is http-01, dns-01 or "" (issued before Citadel recorded it).
	Kind      string `json:"kind"`
	AutoRenew bool   `json:"autoRenew"`
	// Manual: DNS-01, renewed by requesting the certificate again.
	Manual        bool   `json:"manual"`
	NextRenewalAt string `json:"nextRenewalAt,omitempty"`
	LastAttemptAt string `json:"lastAttemptAt,omitempty"`
	LastError     string `json:"lastError,omitempty"`
	Attempts      int    `json:"attempts,omitempty"`
	RenewedBy     string `json:"renewedBy,omitempty"`
}

func leRenewalOut(c store.ACMELECertificate, now time.Time) *leRenewalJSON {
	out := &leRenewalJSON{
		Kind: c.ChallengeKind, AutoRenew: c.AutoRenew, Manual: c.ChallengeKind == store.ACMELEOrderDNS01,
		LastError: c.RenewLastError, Attempts: c.RenewAttempts, RenewedBy: c.RenewedBy,
	}
	if c.RenewLastAttemptAt != nil {
		out.LastAttemptAt = fmtTime(*c.RenewLastAttemptAt)
	}
	if c.AutoRenew && c.RenewedBy == "" && c.Status == "ISSUED" && now.Before(c.NotAfter) {
		next := c.NotAfter.Add(-leRenewWindow)
		if c.RenewNextAttemptAt != nil && c.RenewNextAttemptAt.After(next) {
			next = *c.RenewNextAttemptAt
		}
		if next.Before(now) {
			next = now
		}
		out.NextRenewalAt = fmtTime(next)
	}
	return out
}

// leRenewBackoff is the wait after the given number of consecutive failures.
func leRenewBackoff(failures int) time.Duration {
	d := leRenewBackoffMin
	for i := 1; i < failures && d < leRenewBackoffMax; i++ {
		d *= 2
	}
	return min(d, leRenewBackoffMax)
}

// handleV1SetLEAutoRenew turns automatic renewal on or off.
func (s *Server) handleV1SetLEAutoRenew(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.SetLetsEncryptAutoRenew"
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var req struct {
		CertID    string `json:"certId"`
		AutoRenew *bool  `json:"autoRenew"`
	}
	if !s.decodePKIBody(w, r, &req) {
		return
	}
	id := strings.TrimSpace(req.CertID)
	if id == "" || len(id) > 64 || req.AutoRenew == nil {
		s.writePKIError(w, r, ctx, action, "", pkiInvalid("certId and autoRenew are required"))
		return
	}
	if !s.leSupported() {
		s.writePKIError(w, r, ctx, action, id, errLEUnsupported)
		return
	}
	cert, err := s.store.GetACMELECertificate(ctx, id)
	if err != nil {
		s.writePKIError(w, r, ctx, action, id, pkiNotFound("certificate"))
		return
	}
	clear(cert.KeyDER)
	if *req.AutoRenew && cert.ChallengeKind == store.ACMELEOrderDNS01 {
		s.writePKIError(w, r, ctx, action, id, pkiInvalid("DNS-01 certificates can't renew automatically; request the certificate again to renew it"))
		return
	}
	if err := s.store.SetACMELEAutoRenew(ctx, id, *req.AutoRenew); err != nil {
		s.writePKIError(w, r, ctx, action, id, err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: id, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	cert.AutoRenew, cert.RenewAttempts, cert.RenewNextAttemptAt = *req.AutoRenew, 0, nil
	writeNativeJSON(w, http.StatusOK, map[string]any{"certId": id, "renewal": leRenewalOut(cert, time.Now())})
}

// leRenewJob renews the Let's Encrypt certificates that are due.
func (s *Server) leRenewJob(ctx context.Context) error {
	if !s.leSupported() {
		return nil
	}
	s.renewDueLECertificates(ctx, time.Now().UTC())
	return nil
}

// renewDueLECertificates runs one pass and returns how many renewed.
func (s *Server) renewDueLECertificates(ctx context.Context, now time.Time) int {
	due, err := s.store.ListACMELERenewalsDue(ctx, now.Add(leRenewWindow), now, leRenewBatch)
	if err != nil {
		if !errors.Is(err, store.ErrUnsupported) {
			log.Printf("pki: Let's Encrypt renewal job: list: %v", err)
		}
		return 0
	}
	renewed := 0
	for _, c := range due {
		if ctx.Err() != nil {
			break
		}
		if c.ChallengeKind == store.ACMELEOrderDNS01 {
			continue // never automatic; the flag can't be set, but be safe
		}
		ok, err := s.store.ClaimACMELERenewal(ctx, c.CertID, now, now.Add(leRenewLease))
		if err != nil {
			log.Printf("pki: Let's Encrypt renewal job: claim %s: %v", c.CertID, err)
			continue
		}
		if !ok {
			continue // another replica has it
		}
		if s.renewLECertificate(ctx, c) {
			renewed++
		}
	}
	return renewed
}

// renewLECertificate renews one claimed certificate and records the outcome.
func (s *Server) renewLECertificate(ctx context.Context, c store.ACMELECertificate) bool {
	actx := store.WithCallerAccount(ctx, c.AccountID)
	origin := store.AuditOrigin{Actor: leRenewActor, ActorType: store.AuditActorSystem, AccountID: c.AccountID, Resource: c.CertID}
	domains := normalizeDomains([]string{c.Domains})
	order := store.ACMELEOrder{
		OrderID: cryptoutil.RandomHex(12), DirectoryURL: s.acmeLEDirectoryURL(actx), Domains: strings.Join(domains, ","),
		Status: store.ACMELEOrderProcessing, Kind: store.ACMELEOrderHTTP01, Progress: "Renewing automatically",
	}
	if err := s.store.CreateACMELEOrder(actx, order); err != nil {
		log.Printf("pki: Let's Encrypt renewal of %s: create order: %v", c.CertID, err)
		order.OrderID = "" // renew anyway; progress just isn't visible
	}
	progress := func(step string) {
		if order.OrderID == "" {
			return
		}
		order.Progress = step
		if err := s.store.UpdateACMELEOrder(actx, order); err != nil {
			log.Printf("pki: Let's Encrypt renewal order %s: record progress: %v", order.OrderID, err)
		}
	}
	octx, cancel := context.WithTimeout(actx, acmeOrderTimeout)
	var (
		cert store.ACMELECertificate
		err  error
	)
	if len(domains) == 0 {
		err = pkiInvalid("the certificate has no domains to renew")
	} else {
		cert, err = s.leIssue()(octx, domains, progress)
	}
	cancel()

	// Record the outcome even if the job is stopping.
	rctx, rcancel := context.WithTimeout(context.WithoutCancel(actx), 10*time.Second)
	defer rcancel()
	now := time.Now().UTC()
	if err != nil {
		msg := leErrorMessage(err)
		next := now.Add(leRenewBackoff(c.RenewAttempts + 1))
		log.Printf("ALERT pki: Let's Encrypt automatic renewal of %s (%s) failed (attempt %d, next %s): %v",
			c.CertID, c.Domains, c.RenewAttempts+1, next.Format(time.RFC3339), err)
		if rerr := s.store.RecordACMELERenewal(rctx, c.CertID, store.ACMELERenewalResult{At: now, Error: msg, NextAttemptAt: next}); rerr != nil {
			log.Printf("pki: Let's Encrypt renewal of %s: record failure: %v", c.CertID, rerr)
		}
		if order.OrderID != "" {
			order.Status, order.Progress, order.Error = store.ACMELEOrderFailed, "", msg
			_ = s.store.UpdateACMELEOrder(rctx, order)
		}
		s.recordAudit(rctx, store.AuditEvent{Action: "citadel.LetsEncryptAutoRenewFailed", KeyID: c.CertID, Result: "error", ErrorType: "letsencrypt_failed", AuditOrigin: origin})
		return false
	}
	if rerr := s.store.RecordACMELERenewal(rctx, c.CertID, store.ACMELERenewalResult{At: now, NewCertID: cert.CertID}); rerr != nil {
		log.Printf("pki: Let's Encrypt renewal of %s: record success: %v", c.CertID, rerr)
	}
	if order.OrderID != "" {
		order.Status, order.Progress, order.Error, order.CertID = store.ACMELEOrderIssued, "", "", cert.CertID
		_ = s.store.UpdateACMELEOrder(rctx, order)
	}
	s.recordAudit(rctx, store.AuditEvent{Action: "citadel.LetsEncryptAutoRenew", KeyID: cert.CertID, Result: "ok", AuditOrigin: origin})
	return true
}
