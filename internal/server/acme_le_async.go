package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
	"golang.org/x/crypto/acme"
)

// Asynchronous Let's Encrypt issuance.
//
// An ACME order can take minutes (validation, then finalization), longer
// than the server's 30 s WriteTimeout. So the requests only start the work:
//
//	POST /v1/certificates/letsencrypt/request        HTTP-01: creates an order row, starts issuance, 202 {orderId}
//	POST /v1/certificates/letsencrypt/dns/begin      DNS-01: creates the ACME order, returns the TXT records (bounded, synchronous)
//	POST /v1/certificates/letsencrypt/dns/complete   DNS-01: starts validation and finalization, 202 {orderId}
//	GET  /v1/certificates/letsencrypt/orders?id=     the order's status, progress, error and certificate
//
// The work runs on the replica that accepted the request, in a goroutine
// tracked by the job runner (s.jobs.Go), bounded by acmeOrderTimeout and
// cancelled on shutdown. Progress is written to the order row, so a poll can
// land on any replica. A row left "processing" by a replica that stopped is
// reported as failed once it is older than the timeout.

// leStaleAfter is when a processing order whose row hasn't moved is
// considered abandoned (its replica stopped).
const leStaleAfter = acmeOrderTimeout + time.Minute

// leIssueFunc and leCompleteFunc are the issuance steps; tests replace them.
type (
	leIssueFunc    func(ctx context.Context, domains []string, progress func(string)) (store.ACMELECertificate, error)
	leCompleteFunc func(ctx context.Context, order store.ACMELEOrder, progress func(string)) (store.ACMELECertificate, error)
)

func (s *Server) leIssue() leIssueFunc {
	if s.testLEIssue != nil {
		return s.testLEIssue
	}
	return s.issueLetsEncryptCertificate
}

func (s *Server) leComplete() leCompleteFunc {
	if s.testLEComplete != nil {
		return s.testLEComplete
	}
	return s.completeLEDNSOrder
}

// leOrderJSON is an order as GET /v1/certificates/letsencrypt/orders returns it.
type leOrderJSON struct {
	OrderID   string `json:"orderId"`
	Kind      string `json:"kind"`
	Status    string `json:"status"`
	Progress  string `json:"progress,omitempty"`
	Error     string `json:"error,omitempty"`
	CertID    string `json:"certId,omitempty"`
	Domains   string `json:"domains"`
	CreatedAt string `json:"createdAt,omitempty"`
	UpdatedAt string `json:"updatedAt,omitempty"`
}

func leOrderOut(o store.ACMELEOrder, now time.Time) leOrderJSON {
	out := leOrderJSON{
		OrderID: o.OrderID, Kind: o.Kind, Status: o.Status, Progress: o.Progress, Error: o.Error, CertID: o.CertID,
		Domains: o.Domains, CreatedAt: fmtTime(o.CreatedAt), UpdatedAt: fmtTime(o.UpdatedAt),
	}
	if o.Status == store.ACMELEOrderProcessing && !o.UpdatedAt.IsZero() && now.Sub(o.UpdatedAt) > leStaleAfter {
		out.Status = store.ACMELEOrderFailed
		out.Error = "The order stopped without finishing (the Citadel replica running it may have restarted). Request the certificate again."
		out.Progress = ""
	}
	return out
}

// leErrorMessage turns an issuance error into a message for the console:
// what the ACME server reported, or a generic one (details go to the log).
func leErrorMessage(err error) string {
	var authzErr *acme.AuthorizationError
	var acmeErr *acme.Error
	var pe *pkiError
	switch {
	case errors.As(err, &pe):
		return pe.msg
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Sprintf("Let's Encrypt didn't finish within %d minutes. Check that the domains point at this server (HTTP-01) or that the TXT records have propagated (DNS-01), then try again.", int(acmeOrderTimeout/time.Minute))
	case errors.Is(err, context.Canceled):
		return "The order was interrupted because Citadel shut down. Request the certificate again."
	case errors.As(err, &authzErr):
		return "Validation failed: " + truncate(authzErr.Error(), 500)
	case errors.As(err, &acmeErr):
		msg := acmeErr.Detail
		if msg == "" {
			msg = acmeErr.ProblemType
		}
		return "Let's Encrypt refused the request: " + truncate(msg, 500)
	default:
		return "The Let's Encrypt request failed; see the server log for details."
	}
}

// startLEOrder runs work for order in the background and records the
// outcome on the order row and in the audit log (as action, with the
// requester's identity carried on ctx).
func (s *Server) startLEOrder(ctx context.Context, r *http.Request, action string, order store.ACMELEOrder, work func(context.Context, func(string)) (store.ACMELECertificate, error)) {
	origin := s.auditOrigin(r)
	s.jobs.Go("letsencrypt-order-"+order.OrderID, ctx, acmeOrderTimeout, func(ctx context.Context) {
		progress := func(step string) {
			order.Progress = step
			if err := s.store.UpdateACMELEOrder(ctx, order); err != nil {
				log.Printf("pki: Let's Encrypt order %s: record progress: %v", order.OrderID, err)
			}
		}
		cert, err := work(ctx, progress)
		// Record the outcome even when ctx is done (timeout, shutdown).
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err != nil {
			log.Printf("pki: Let's Encrypt order %s (%s) failed: %v", order.OrderID, order.Domains, err)
			order.Status, order.Progress, order.Error = store.ACMELEOrderFailed, "", leErrorMessage(err)
			if uerr := s.store.UpdateACMELEOrder(rctx, order); uerr != nil {
				log.Printf("pki: Let's Encrypt order %s: record failure: %v", order.OrderID, uerr)
			}
			s.recordAudit(rctx, store.AuditEvent{Action: action, KeyID: order.OrderID, Result: "error", ErrorType: "letsencrypt_failed", AuditOrigin: origin})
			return
		}
		order.Status, order.Progress, order.Error, order.CertID = store.ACMELEOrderIssued, "", "", cert.CertID
		if uerr := s.store.UpdateACMELEOrder(rctx, order); uerr != nil {
			log.Printf("pki: Let's Encrypt order %s: record success: %v", order.OrderID, uerr)
		}
		s.recordAudit(rctx, store.AuditEvent{Action: action, KeyID: cert.CertID, Result: "ok", AuditOrigin: origin})
	})
}

// leSupported reports whether Let's Encrypt issuance can run (it needs the
// database-backed store).
func (s *Server) leSupported() bool {
	return s.storeDB() != nil
}

var errLEUnsupported = &pkiError{status: http.StatusNotImplemented, code: "unsupported", msg: "Let's Encrypt issuance requires a database-backed store"}

// handleV1RequestLECert starts HTTP-01 issuance and returns the order to poll.
func (s *Server) handleV1RequestLECert(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.RequestLetsEncrypt"
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var req struct {
		Domains string `json:"domains"`
	}
	if !s.decodePKIBody(w, r, &req) {
		return
	}
	domains := normalizeDomains([]string{req.Domains})
	if len(domains) == 0 {
		s.writePKIError(w, r, ctx, action, "", pkiInvalid("at least one domain is required"))
		return
	}
	for _, d := range domains {
		if strings.HasPrefix(d, "*.") {
			s.writePKIError(w, r, ctx, action, req.Domains, pkiInvalid("wildcard names need DNS-01"))
			return
		}
	}
	if !s.leSupported() {
		s.writePKIError(w, r, ctx, action, req.Domains, errLEUnsupported)
		return
	}
	order := store.ACMELEOrder{
		OrderID: cryptoutil.RandomHex(12), DirectoryURL: s.acmeLEDirectoryURL(ctx), Domains: strings.Join(domains, ","),
		Status: store.ACMELEOrderProcessing, Kind: store.ACMELEOrderHTTP01, Progress: "Starting",
	}
	if err := s.store.CreateACMELEOrder(ctx, order); err != nil {
		s.writePKIError(w, r, ctx, action, req.Domains, leFailure("Let's Encrypt request", err))
		return
	}
	issue := s.leIssue()
	s.startLEOrder(ctx, r, action, order, func(ctx context.Context, progress func(string)) (store.ACMELECertificate, error) {
		return issue(ctx, domains, progress)
	})
	writeNativeJSON(w, http.StatusAccepted, map[string]any{
		"requested": true, "orderId": order.OrderID, "status": order.Status, "domains": order.Domains,
	})
}

// handleV1BeginLEDNSOrder starts a manual DNS-01 Let's Encrypt order and
// returns the TXT records to publish.
func (s *Server) handleV1BeginLEDNSOrder(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.BeginLetsEncryptDNS"
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var req struct {
		Domains string `json:"domains"`
	}
	if !s.decodePKIBody(w, r, &req) {
		return
	}
	if len(normalizeDomains([]string{req.Domains})) == 0 {
		s.writePKIError(w, r, ctx, action, "", pkiInvalid("at least one domain is required"))
		return
	}
	if !s.leSupported() {
		s.writePKIError(w, r, ctx, action, req.Domains, errLEUnsupported)
		return
	}
	orderID, records, err := s.beginLEDNSOrder(ctx, []string{req.Domains})
	if err != nil {
		s.writePKIError(w, r, ctx, action, req.Domains, leFailure("starting the DNS-01 order", err))
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: orderID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	recs := make([]map[string]any, 0, len(records))
	for _, rec := range records {
		recs = append(recs, map[string]any{"domain": rec.Domain, "name": rec.Name, "value": rec.Value})
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"orderId": orderID, "records": recs})
}

// handleV1CompleteLEDNSOrder starts validating the published DNS-01 records
// and finalizing a previously begun order, and returns the order to poll.
// A failed order can be retried (after fixing the records).
func (s *Server) handleV1CompleteLEDNSOrder(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.CompleteLetsEncryptDNS"
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var req struct {
		OrderID string `json:"orderId"`
	}
	if !s.decodePKIBody(w, r, &req) {
		return
	}
	orderID := strings.TrimSpace(req.OrderID)
	if orderID == "" || len(orderID) > 64 {
		s.writePKIError(w, r, ctx, action, "", pkiInvalid("orderId is required"))
		return
	}
	if !s.leSupported() {
		s.writePKIError(w, r, ctx, action, orderID, errLEUnsupported)
		return
	}
	order, err := s.store.GetACMELEOrder(ctx, orderID)
	if err != nil || order.Kind != store.ACMELEOrderDNS01 {
		s.writePKIError(w, r, ctx, action, orderID, &pkiError{status: http.StatusNotFound, code: "not_found", msg: "Let's Encrypt order not found"})
		return
	}
	// One request (on any replica) starts the work.
	started, err := s.store.TransitionACMELEOrder(ctx, orderID, []string{store.ACMELEOrderPending, store.ACMELEOrderFailed}, store.ACMELEOrderProcessing, "Starting validation")
	if err != nil {
		s.writePKIError(w, r, ctx, action, orderID, leFailure("completing the DNS-01 order", err))
		return
	}
	if !started {
		cur, _ := s.store.GetACMELEOrder(ctx, orderID)
		out := leOrderOut(cur, time.Now())
		if out.Status == store.ACMELEOrderProcessing || out.Status == store.ACMELEOrderIssued {
			// Already running or done: report it rather than fail.
			writeNativeJSON(w, http.StatusAccepted, out)
			return
		}
		s.writePKIError(w, r, ctx, action, orderID, &pkiError{status: http.StatusConflict, code: "order_conflict", msg: "the order can't be completed in its current state"})
		return
	}
	order.Status, order.Progress, order.Error = store.ACMELEOrderProcessing, "Starting validation", ""
	complete := s.leComplete()
	s.startLEOrder(ctx, r, action, order, func(ctx context.Context, progress func(string)) (store.ACMELECertificate, error) {
		return complete(ctx, order, progress)
	})
	writeNativeJSON(w, http.StatusAccepted, leOrderOut(order, time.Now()))
}

// handleV1GetLEOrder reports an order's status for the console to poll.
func (s *Server) handleV1GetLEOrder(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" || len(id) > 64 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	if !s.leSupported() {
		writeNativeError(w, http.StatusNotImplemented, "unsupported", errLEUnsupported.msg)
		return
	}
	order, err := s.store.GetACMELEOrder(ctx, id)
	if err != nil {
		writeNativeError(w, http.StatusNotFound, "not_found", "Let's Encrypt order not found")
		return
	}
	writeNativeJSON(w, http.StatusOK, leOrderOut(order, time.Now()))
}
