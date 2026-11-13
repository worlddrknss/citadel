package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// Deleting certificates and certificate authorities.
//
// Certificates (admin):
//
//	DELETE /v1/certificates?source=&id=   pca-cert, lets-encrypt or acm-imported
//
// A private CA certificate that is still trusted (unexpired, unrevoked) is
// revoked first (CessationOfOperation) so deleting it from the inventory
// never leaves a trusted certificate nobody can see; its row is kept so the
// CRL keeps listing it. Let's Encrypt and imported certificates are removed
// with their keys.
//
// Certificate authorities follow AWS ACM PCA (admin):
//
//	POST /v1/certificates/authorities/status   {caId, status: ACTIVE|DISABLED}
//	POST /v1/certificates/authorities/delete   {caId, permanentDeletionTimeInDays}
//	POST /v1/certificates/authorities/restore  {caId}
//
// A CA must be DISABLED before deletion. Deletion is refused while the CA has
// issued certificates (or subordinate CAs) that are still trusted: revoke
// them first. A deleted CA is DELETED with a restore window of 7 to 30 days
// (default 30); RestoreCertificateAuthority returns it to DISABLED, and the
// "pki-ca-purge" job removes it, with its certificates, once the window ends.
// The same operations are on the AWS API (UpdateCertificateAuthority,
// DeleteCertificateAuthority, RestoreCertificateAuthority).

const (
	caDeletionMinDays     = 7
	caDeletionMaxDays     = 30
	caDeletionDefaultDays = 30
	caPurgeInterval       = time.Hour
	caPurgeActor          = "pki-ca-purge-job"
)

// caDeletableStates are the states DeleteCertificateAuthority starts from:
// disabled or expired CAs, and (as AWS allows) CAs that never became active.
var caDeletableStates = []string{store.CAStateDisabled, "EXPIRED", "PENDING_CERTIFICATE", "CREATING", "FAILED"}

func init() {
	pcaActions["UpdateCertificateAuthority"] = (*Server).pcaUpdateCertificateAuthority
	pcaActions["DeleteCertificateAuthority"] = (*Server).pcaDeleteCertificateAuthority
	pcaActions["RestoreCertificateAuthority"] = (*Server).pcaRestoreCertificateAuthority
}

func (s *Server) registerPKILifecycle(mux *http.ServeMux) {
	s.jobs.Every("pki-ca-purge", caPurgeInterval, s.caPurgeJob)
	s.jobs.Every("letsencrypt-renew", leRenewInterval, s.leRenewJob)
	mux.HandleFunc("POST /v1/certificates/letsencrypt/auto-renew", s.handleV1SetLEAutoRenew)
	mux.HandleFunc("DELETE /v1/certificates", s.handleV1DeleteCertificate)
	mux.HandleFunc("POST /v1/certificates/authorities/status", s.handleV1SetCAStatus)
	mux.HandleFunc("POST /v1/certificates/authorities/delete", s.handleV1DeleteCA)
	mux.HandleFunc("POST /v1/certificates/authorities/restore", s.handleV1RestoreCA)
}

// ---- shared operations ----

func caStateError(ca store.PCACertificateAuthority, want string) error {
	return pkiConflict("InvalidStateException", "certificate authority is %s; %s", strings.ToLower(ca.State), want)
}

// pkiSetCAStatus enables or disables a CA.
func (s *Server) pkiSetCAStatus(ctx context.Context, rec store.PCACertificateAuthority, status string) (store.PCACertificateAuthority, error) {
	status = strings.ToUpper(strings.TrimSpace(status))
	var from []string
	switch status {
	case store.CAStateActive:
		from = []string{store.CAStateDisabled, store.CAStateActive}
		if time.Now().After(rec.NotAfter) {
			return rec, pkiConflict("InvalidStateException", "certificate authority has expired and can't be enabled")
		}
	case store.CAStateDisabled:
		from = []string{store.CAStateActive, store.CAStateDisabled}
	default:
		return rec, pkiInvalid("status must be ACTIVE or DISABLED")
	}
	ca, err := s.store.TransitionCertificateAuthority(ctx, rec.CAID, from, status, nil)
	if errors.Is(err, store.ErrCAStateConflict) {
		return ca, caStateError(ca, "only active and disabled CAs can change status")
	}
	return ca, err
}

// pkiDeleteCA schedules a disabled CA's deletion.
func (s *Server) pkiDeleteCA(ctx context.Context, rec store.PCACertificateAuthority, days int) (store.PCACertificateAuthority, error) {
	if days == 0 {
		days = caDeletionDefaultDays
	}
	if days < caDeletionMinDays || days > caDeletionMaxDays {
		return rec, pkiInvalid("PermanentDeletionTimeInDays must be between %d and %d", caDeletionMinDays, caDeletionMaxDays)
	}
	if rec.State == store.CAStateActive {
		return rec, caStateError(rec, "disable it before deleting it")
	}
	now := time.Now().UTC()
	n, err := s.store.CountOutstandingCertificates(ctx, rec.CAID, now)
	if err != nil {
		return rec, err
	}
	if n > 0 {
		return rec, pkiConflict("InvalidStateException",
			"certificate authority has %d certificate%s that %s still valid; revoke %s first", n, pluralS(n), isAre(n), themIt(n))
	}
	until := now.Add(time.Duration(days) * 24 * time.Hour)
	ca, err := s.store.TransitionCertificateAuthority(ctx, rec.CAID, caDeletableStates, store.CAStateDeleted, &until)
	if errors.Is(err, store.ErrCAStateConflict) {
		return ca, caStateError(ca, "disable it before deleting it")
	}
	return ca, err
}

// pkiRestoreCA restores a deleted CA within its window, to DISABLED.
func (s *Server) pkiRestoreCA(ctx context.Context, rec store.PCACertificateAuthority) (store.PCACertificateAuthority, error) {
	if rec.State != store.CAStateDeleted {
		return rec, caStateError(rec, "only deleted CAs can be restored")
	}
	if rec.RestorableUntil != nil && !time.Now().Before(*rec.RestorableUntil) {
		return rec, caStateError(rec, "its restore window has ended")
	}
	ca, err := s.store.TransitionCertificateAuthority(ctx, rec.CAID, []string{store.CAStateDeleted}, store.CAStateDisabled, nil)
	if errors.Is(err, store.ErrCAStateConflict) {
		return ca, caStateError(ca, "only deleted CAs can be restored")
	}
	return ca, err
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func isAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

func themIt(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}

// caPurgeJob permanently removes deleted CAs whose restore window ended.
func (s *Server) caPurgeJob(ctx context.Context) error {
	s.purgeDeletedCAs(ctx, time.Now().UTC())
	return nil
}

func (s *Server) purgeDeletedCAs(ctx context.Context, now time.Time) int {
	due, err := s.store.ListCertificateAuthoritiesDueForPurge(ctx, now)
	if err != nil {
		log.Printf("pki: CA purge job: list: %v", err)
		return 0
	}
	n := 0
	for _, ca := range due {
		if ctx.Err() != nil {
			break
		}
		origin := store.AuditOrigin{Actor: caPurgeActor, ActorType: store.AuditActorSystem, AccountID: ca.AccountID, Resource: ca.ARN}
		actx, aerr := s.beginJobAudit(store.WithCallerAccount(ctx, ca.AccountID), store.AuditEvent{Action: "citadel.PurgeCertificateAuthority", KeyID: ca.CAID, AuditOrigin: origin})
		if aerr != nil {
			continue // not attempted; the next run retries
		}
		ok, err := s.store.PurgeCertificateAuthority(actx, ca.CAID, now)
		switch {
		case err != nil:
			log.Printf("pki: CA purge job: purge %s: %v", ca.CAID, err)
			s.recordAudit(actx, store.AuditEvent{Action: "citadel.PurgeCertificateAuthority", KeyID: ca.CAID, Result: "error", ErrorType: "InternalError", AuditOrigin: origin})
		case ok:
			n++
			s.recordAudit(actx, store.AuditEvent{Action: "citadel.PurgeCertificateAuthority", KeyID: ca.CAID, Result: "ok", AuditOrigin: origin})
		default:
			s.finishAudit(actx, store.AuditResultError, "NotDue") // restored or purged elsewhere meanwhile
		}
	}
	return n
}

// ---- native handlers ----

type nativeCAActionRequest struct {
	CAID                        string  `json:"caId"`
	Status                      string  `json:"status"`
	PermanentDeletionTimeInDays flexInt `json:"permanentDeletionTimeInDays"`
}

func (s *Server) nativeCAAction(w http.ResponseWriter, r *http.Request, action string, op func(context.Context, store.PCACertificateAuthority, nativeCAActionRequest) (store.PCACertificateAuthority, error)) {
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req nativeCAActionRequest
	if !s.decodePKIBody(w, r, &req) {
		return
	}
	caID := strings.TrimSpace(req.CAID)
	if caID == "" || len(caID) > 128 {
		s.writePKIError(w, r, ctx, action, "", pkiInvalid("caId is required"))
		return
	}
	rec, err := s.store.GetCertificateAuthorityByID(ctx, caID)
	if err != nil {
		s.writePKIError(w, r, ctx, action, caID, err)
		return
	}
	ca, err := op(ctx, rec, req)
	if err != nil {
		s.writePKIError(w, r, ctx, action, caID, err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: caID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	out := map[string]any{"caId": ca.CAID, "status": ca.State}
	if ca.RestorableUntil != nil {
		out["restorableUntil"] = fmtTime(*ca.RestorableUntil)
	}
	writeNativeJSON(w, http.StatusOK, out)
}

func (s *Server) handleV1SetCAStatus(w http.ResponseWriter, r *http.Request) {
	s.nativeCAAction(w, r, "citadel.UpdateCAStatus", func(ctx context.Context, rec store.PCACertificateAuthority, req nativeCAActionRequest) (store.PCACertificateAuthority, error) {
		return s.pkiSetCAStatus(ctx, rec, req.Status)
	})
}

func (s *Server) handleV1DeleteCA(w http.ResponseWriter, r *http.Request) {
	s.nativeCAAction(w, r, "citadel.DeleteCA", func(ctx context.Context, rec store.PCACertificateAuthority, req nativeCAActionRequest) (store.PCACertificateAuthority, error) {
		return s.pkiDeleteCA(ctx, rec, int(req.PermanentDeletionTimeInDays))
	})
}

func (s *Server) handleV1RestoreCA(w http.ResponseWriter, r *http.Request) {
	s.nativeCAAction(w, r, "citadel.RestoreCA", func(ctx context.Context, rec store.PCACertificateAuthority, _ nativeCAActionRequest) (store.PCACertificateAuthority, error) {
		return s.pkiRestoreCA(ctx, rec)
	})
}

// handleV1DeleteCertificate deletes a certificate from the inventory.
func (s *Server) handleV1DeleteCertificate(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.DeleteCertificate"
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	q := r.URL.Query()
	source, id := strings.TrimSpace(q.Get("source")), strings.TrimSpace(q.Get("id"))
	if id == "" || len(id) > 2048 {
		s.writePKIError(w, r, ctx, action, "", pkiInvalid("source and id are required"))
		return
	}
	revoked := false
	err := func() error {
		switch source {
		case "pca-cert":
			c, err := s.store.GetCertificate(ctx, id)
			if err != nil {
				return err
			}
			if c.DeletedAt != nil {
				return store.ErrCertificateNotFound
			}
			if c.Status != "REVOKED" && c.RevokedAt == nil && time.Now().Before(c.NotAfter) {
				reason, _, _ := normalizeRevocationReason("CessationOfOperation")
				if err := s.store.RevokeCertificate(ctx, id, reason); err != nil && !errors.Is(err, store.ErrCertificateAlreadyRevoked) {
					return err
				}
				revoked = true
			}
			return s.store.HideCertificate(ctx, id, time.Now().UTC())
		case "lets-encrypt":
			if !s.leSupported() {
				return errLEUnsupported
			}
			return s.store.DeleteACMELECertificate(ctx, id)
		case sourceACMImported:
			c, err := s.store.GetACMCertificate(ctx, id)
			if err != nil {
				return err
			}
			clear(c.KeyDER)
			if c.Type != store.ACMTypeImported {
				return pkiInvalid("only imported certificates can be deleted")
			}
			return s.store.DeleteACMCertificate(ctx, id)
		case "pca-ca":
			return pkiInvalid("delete certificate authorities with /v1/certificates/authorities/delete")
		default:
			return pkiInvalid("unknown certificate source")
		}
	}()
	if err != nil {
		s.writePKIError(w, r, ctx, action, id, err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: id, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"source": source, "id": id, "deleted": true, "revoked": revoked})
}

// ---- AWS ACM PCA ----

type pcaCAArnRequest struct {
	CertificateAuthorityArn     string `json:"CertificateAuthorityArn"`
	Status                      string `json:"Status"`
	PermanentDeletionTimeInDays int    `json:"PermanentDeletionTimeInDays"`
}

func (s *Server) pcaLoadForLifecycle(ctx context.Context, body []byte) (pcaCAArnRequest, store.PCACertificateAuthority, error) {
	var req pcaCAArnRequest
	if err := decodeAWS(body, &req); err != nil {
		return req, store.PCACertificateAuthority{}, err
	}
	if req.CertificateAuthorityArn == "" {
		return req, store.PCACertificateAuthority{}, pkiInvalid("CertificateAuthorityArn is required")
	}
	rec, err := s.store.DescribeCertificateAuthority(ctx, req.CertificateAuthorityArn)
	return req, rec, err
}

func (s *Server) pcaUpdateCertificateAuthority(ctx context.Context, body []byte) (any, string, error) {
	req, rec, err := s.pcaLoadForLifecycle(ctx, body)
	if err != nil {
		return nil, req.CertificateAuthorityArn, err
	}
	if req.Status == "" {
		return nil, rec.ARN, nil // only RevocationConfiguration, which Citadel doesn't model
	}
	_, err = s.pkiSetCAStatus(ctx, rec, req.Status)
	return nil, rec.ARN, err
}

func (s *Server) pcaDeleteCertificateAuthority(ctx context.Context, body []byte) (any, string, error) {
	req, rec, err := s.pcaLoadForLifecycle(ctx, body)
	if err != nil {
		return nil, req.CertificateAuthorityArn, err
	}
	_, err = s.pkiDeleteCA(ctx, rec, req.PermanentDeletionTimeInDays)
	return nil, rec.ARN, err
}

func (s *Server) pcaRestoreCertificateAuthority(ctx context.Context, body []byte) (any, string, error) {
	req, rec, err := s.pcaLoadForLifecycle(ctx, body)
	if err != nil {
		return nil, req.CertificateAuthorityArn, err
	}
	_, err = s.pkiRestoreCA(ctx, rec)
	return nil, rec.ARN, err
}

// caLifecycleRow fills the deletion details of a console CA row.
func (s *Server) caLifecycleRow(ctx context.Context, row *nativeCertificate, ca store.PCACertificateAuthority, now time.Time) {
	if ca.RestorableUntil != nil {
		row.RestorableUntil = fmtTime(*ca.RestorableUntil)
	}
	if ca.State == store.CAStateDeleted {
		return
	}
	if n, err := s.store.CountOutstandingCertificates(ctx, ca.CAID, now); err == nil {
		row.Outstanding = &n
	} else {
		log.Printf("pki: count outstanding certificates of %s: %v", ca.CAID, err)
	}
}
