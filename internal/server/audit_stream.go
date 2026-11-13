package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// SIEM streaming: each account may forward its audit events to an https
// webhook as JSON or CEF, with an optional bearer token sealed at rest.
// Events are queued in an outbox in the same transaction that records them
// and delivered by a background job (one ticker goroutine per process,
// started by New and stopped by Close) with exponential backoff.

// auditRuntime is the server's audit state: export rate limiting and the
// stream delivery job. The zero value is ready to use.
type auditRuntime struct {
	mu      sync.Mutex
	exports map[string][]time.Time

	jobStop chan struct{}
	jobDone chan struct{}

	// outcomes holds write-ahead outcome events awaiting retry.
	outcomes auditOutcomeQueue

	// client overrides the webhook HTTP client (tests).
	client *http.Client
}

const (
	auditStreamTick        = 5 * time.Second
	auditStreamBatch       = 50
	auditStreamLease       = 2 * time.Minute
	auditStreamMaxAttempts = 15
	auditStreamMaxBackoff  = time.Hour
	auditStreamTimeout     = 10 * time.Second
	auditStreamTokenMax    = 4096
	auditStreamURLMax      = 2048
)

// startAuditStreamJob starts the outbox delivery loop.
func (s *Server) startAuditStreamJob() {
	rt := &s.audit
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.jobStop != nil {
		return
	}
	rt.jobStop = make(chan struct{})
	rt.jobDone = make(chan struct{})
	go func(stop <-chan struct{}, done chan<- struct{}) {
		defer close(done)
		t := time.NewTicker(auditStreamTick)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				ctx, cancel := context.WithTimeout(context.Background(), auditStreamLease)
				s.deliverAuditOutbox(ctx)
				cancel()
			}
		}
	}(rt.jobStop, rt.jobDone)
}

// Close stops the server's background jobs. It is safe to call more than
// once and on a server whose jobs never started.
func (s *Server) Close() {
	rt := &s.audit
	rt.mu.Lock()
	stop, done := rt.jobStop, rt.jobDone
	rt.jobStop, rt.jobDone = nil, nil
	rt.mu.Unlock()
	if stop != nil {
		close(stop)
		<-done
	}
}

// deliverAuditOutbox runs one delivery round.
func (s *Server) deliverAuditOutbox(ctx context.Context) {
	items, err := s.store.ClaimAuditOutbox(ctx, auditStreamBatch, auditStreamLease)
	if err != nil {
		log.Printf("audit stream: claim failed: %v", err)
		return
	}
	configs := map[string]store.AuditStreamConfig{}
	for _, it := range items {
		acct := it.Event.AccountID
		cfg, ok := configs[acct]
		if !ok {
			if cfg, err = s.store.GetAuditStreamConfig(ctx, acct); err != nil {
				log.Printf("audit stream: config read failed account=%s: %v", acct, err)
				continue // the lease expires and the item is retried
			}
			configs[acct] = cfg
		}
		if !cfg.Enabled || cfg.URL == "" {
			// Streaming was turned off after the event was queued.
			_ = s.store.CompleteAuditOutbox(ctx, it.ID)
			continue
		}
		status, err := s.sendAuditEvent(ctx, cfg, it.Event)
		if err == nil {
			if cerr := s.store.CompleteAuditOutbox(ctx, it.ID); cerr != nil {
				log.Printf("audit stream: complete failed id=%d: %v", it.ID, cerr)
			}
			continue
		}
		attempts := it.Attempts + 1
		dead := attempts >= auditStreamMaxAttempts
		backoff := auditStreamTick << min(attempts, 20)
		if backoff > auditStreamMaxBackoff || backoff <= 0 {
			backoff = auditStreamMaxBackoff
		}
		msg := err.Error()
		if status != 0 {
			msg = fmt.Sprintf("HTTP %d", status)
		}
		log.Printf("audit stream: delivery failed account=%s event=%d attempt=%d dead=%t: %s", acct, it.Event.ID, attempts, dead, msg)
		if rerr := s.store.RetryAuditOutbox(ctx, it.ID, time.Now().Add(backoff), msg, dead); rerr != nil {
			log.Printf("audit stream: retry bookkeeping failed id=%d: %v", it.ID, rerr)
		}
	}
}

// ---- payloads --------------------------------------------------------------

func auditStreamBody(format string, rec store.AuditRecord) ([]byte, string) {
	if format == "cef" {
		return []byte(auditCEF(rec)), "text/plain; charset=utf-8"
	}
	e := toAuditEventJSON(rec)
	e.HashValid = nil
	payload := struct {
		auditEventJSON
		AccountID string `json:"accountId"`
	}{e, rec.AccountID}
	b, _ := json.Marshal(payload)
	return b, "application/json"
}

func cefHeaderEscape(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, "|", `\|`)
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(v)
}

func cefExtEscape(v string) string {
	return strings.NewReplacer(`\`, `\\`, "=", `\=`, "\r", `\r`, "\n", `\n`).Replace(v)
}

// auditCEF renders rec as one ArcSight Common Event Format line.
func auditCEF(rec store.AuditRecord) string {
	result := store.NormalizeAuditResult(rec.Result, rec.ErrorType)
	severity := "3"
	switch result {
	case store.AuditResultDenied:
		severity = "7"
	case store.AuditResultError:
		severity = "5"
	}
	var ext []string
	add := func(k, v string) {
		if v != "" {
			ext = append(ext, k+"="+cefExtEscape(v))
		}
	}
	add("rt", strconv.FormatInt(rec.CreatedAt.UnixMilli(), 10))
	add("externalId", strconv.FormatInt(rec.ID, 10))
	add("act", rec.Action)
	add("suser", rec.Actor)
	if net.ParseIP(rec.SourceIP) != nil {
		add("src", rec.SourceIP)
	}
	add("requestClientApplication", rec.UserAgent)
	add("outcome", result)
	add("cs1Label", "accountId")
	add("cs1", rec.AccountID)
	if rec.Resource != "" {
		add("cs2Label", "resource")
		add("cs2", rec.Resource)
	}
	if rec.ErrorType != "" {
		add("cs3Label", "errorType")
		add("cs3", rec.ErrorType)
	}
	add("cs4Label", "chainHash")
	add("cs4", rec.EventHash)
	if rec.AccessKeyID != "" {
		add("cs5Label", "accessKeyId")
		add("cs5", rec.AccessKeyID)
	}
	if rec.CorrelationID != "" {
		add("cs6Label", "correlationId")
		add("cs6", rec.CorrelationID)
	}
	if rec.AgentID != "" {
		add("flexString1Label", "agentId")
		add("flexString1", rec.AgentID)
	}
	if rec.TaskID != "" {
		add("flexString2Label", "taskId")
		add("flexString2", rec.TaskID)
	}
	return fmt.Sprintf("CEF:0|Citadel|Citadel|1|%s|%s|%s|%s",
		cefHeaderEscape(rec.Action), cefHeaderEscape(rec.Action), severity, strings.Join(ext, " "))
}

// ---- delivery --------------------------------------------------------------

// auditStreamHTTPClient refuses redirects and connections to loopback,
// link-local (cloud metadata), multicast and unspecified addresses, so the
// webhook cannot be pointed back into the host. Private (RFC 1918) ranges
// are allowed: SIEM collectors usually live there.
func (s *Server) auditStreamHTTPClient() *http.Client {
	if s.audit.client != nil {
		return s.audit.client
	}
	dialer := &net.Dialer{
		Timeout: auditStreamTimeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
				ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
				return errors.New("audit stream destination address is not allowed")
			}
			return nil
		},
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   auditStreamTimeout,
		ResponseHeaderTimeout: auditStreamTimeout,
		MaxIdleConns:          4,
		IdleConnTimeout:       time.Minute,
	}
	return &http.Client{
		Timeout:       auditStreamTimeout,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// sendAuditEvent POSTs rec to cfg's webhook. It returns the HTTP status (0
// when no response) and an error unless the status is 2xx.
func (s *Server) sendAuditEvent(ctx context.Context, cfg store.AuditStreamConfig, rec store.AuditRecord) (int, error) {
	if err := validateStreamURL(cfg.URL); err != nil {
		return 0, err
	}
	body, contentType := auditStreamBody(cfg.Format, rec)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return 0, errors.New("invalid stream request")
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", AppName+"-audit-stream/1")
	if len(cfg.TokenSealed) > 0 {
		token, err := s.openStreamToken(cfg.AccountID, cfg.TokenSealed)
		if err != nil {
			return 0, errors.New("stream token could not be decrypted")
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := s.auditStreamHTTPClient().Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			return 0, errors.New("delivery failed: " + uerr.Err.Error())
		}
		return 0, errors.New("delivery failed")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

// ---- token sealing ---------------------------------------------------------

func (s *Server) streamTokenKey() ([]byte, error) {
	switch {
	case len(s.deploymentSecret()) > 0:
		return cryptoutil.DeriveAuditStreamKey(s.deploymentSecret()), nil
	case len(s.cfg.AuditHMACKey) > 0:
		return cryptoutil.DeriveAuditStreamKey(s.cfg.AuditHMACKey), nil
	}
	return nil, errors.New("no key is configured to seal the stream token")
}

func streamTokenAAD(accountID string) []byte {
	return []byte("citadel/audit-stream-token/v1|" + accountID)
}

func (s *Server) sealStreamToken(accountID, token string) ([]byte, error) {
	key, err := s.streamTokenKey()
	if err != nil {
		return nil, err
	}
	return cryptoutil.GCMSeal(key, []byte(token), streamTokenAAD(accountID))
}

func (s *Server) openStreamToken(accountID string, sealed []byte) (string, error) {
	key, err := s.streamTokenKey()
	if err != nil {
		return "", err
	}
	pt, err := cryptoutil.GCMOpen(key, sealed, streamTokenAAD(accountID))
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// ---- settings API ----------------------------------------------------------

type auditStreamJSON struct {
	Enabled  bool   `json:"enabled"`
	URL      string `json:"url"`
	Format   string `json:"format"`
	HasToken bool   `json:"hasToken"`
}

func toAuditStreamJSON(cfg store.AuditStreamConfig) auditStreamJSON {
	format := cfg.Format
	if format == "" {
		format = "json"
	}
	return auditStreamJSON{Enabled: cfg.Enabled, URL: cfg.URL, Format: format, HasToken: len(cfg.TokenSealed) > 0}
}

// validateStreamURL accepts only absolute https URLs without credentials or
// fragments.
func validateStreamURL(raw string) error {
	if len(raw) > auditStreamURLMax {
		return fmt.Errorf("url must be at most %d characters", auditStreamURLMax)
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return errors.New("url must be an absolute https URL")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return errors.New("url must use https")
	}
	if u.Hostname() == "" {
		return errors.New("url must include a host")
	}
	if u.User != nil {
		return errors.New("url must not contain credentials; use the token field")
	}
	if u.Fragment != "" {
		return errors.New("url must not contain a fragment")
	}
	return nil
}

func validStreamToken(t string) bool {
	if len(t) > auditStreamTokenMax {
		return false
	}
	for i := 0; i < len(t); i++ {
		if t[i] < 0x21 || t[i] > 0x7e { // visible ASCII only: no header injection
			return false
		}
	}
	return true
}

// GET /v1/audit/stream — viewer.
func (s *Server) handleV1GetAuditStream(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	cfg, err := s.store.GetAuditStreamConfig(ctx, s.auditAccount(ctx))
	if err != nil {
		log.Printf("audit stream config read failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "stream_failed", "failed to read the stream settings")
		return
	}
	writeNativeJSON(w, http.StatusOK, toAuditStreamJSON(cfg))
}

// POST /v1/audit/stream — admin. {enabled, url, format, token?}: an omitted
// token keeps the stored one; "" clears it.
func (s *Server) handleV1PutAuditStream(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	const action = "citadel.PutAuditStream"
	var req struct {
		Enabled bool    `json:"enabled"`
		URL     string  `json:"url"`
		Format  string  `json:"format"`
		Token   *string `json:"token"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	req.Format = strings.ToLower(strings.TrimSpace(req.Format))
	if req.Format == "" {
		req.Format = "json"
	}
	fail := func(msg string) {
		s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		writeNativeError(w, http.StatusBadRequest, "invalid_request", msg)
	}
	if req.Format != "json" && req.Format != "cef" {
		fail("format must be json or cef")
		return
	}
	if req.URL != "" || req.Enabled {
		if err := validateStreamURL(req.URL); err != nil {
			fail(err.Error())
			return
		}
	}
	account := s.auditAccount(ctx)
	cfg, err := s.store.GetAuditStreamConfig(ctx, account)
	if err != nil {
		log.Printf("audit stream config read failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "stream_failed", "failed to save the stream settings")
		return
	}
	if req.Token != nil {
		token := strings.TrimSpace(*req.Token)
		if token == "" {
			cfg.TokenSealed = nil
		} else {
			if !validStreamToken(token) {
				fail(fmt.Sprintf("token must be at most %d visible ASCII characters", auditStreamTokenMax))
				return
			}
			sealed, err := s.sealStreamToken(account, token)
			if err != nil {
				log.Printf("audit stream token seal failed: %v", err)
				writeNativeError(w, http.StatusInternalServerError, "stream_failed", "failed to save the stream settings")
				return
			}
			cfg.TokenSealed = sealed
		}
	}
	cfg.AccountID, cfg.Enabled, cfg.URL, cfg.Format, cfg.UpdatedBy = account, req.Enabled, req.URL, req.Format, sess.Username
	origin := s.auditOrigin(r)
	origin.Resource = req.URL
	if err := s.store.PutAuditStreamConfig(ctx, cfg); err != nil {
		log.Printf("audit stream config write failed: %v", err)
		s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "error", ErrorType: "InternalFailure", AuditOrigin: origin})
		writeNativeError(w, http.StatusInternalServerError, "stream_failed", "failed to save the stream settings")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "ok", AuditOrigin: origin})
	writeNativeJSON(w, http.StatusOK, toAuditStreamJSON(cfg))
}

// POST /v1/audit/stream/test — admin. Sends one synthetic event to the
// configured webhook now.
func (s *Server) handleV1TestAuditStream(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	const action = "citadel.TestAuditStream"
	account := s.auditAccount(ctx)
	cfg, err := s.store.GetAuditStreamConfig(ctx, account)
	if err != nil {
		log.Printf("audit stream config read failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "stream_failed", "failed to read the stream settings")
		return
	}
	origin := s.auditOrigin(r)
	origin.Resource = cfg.URL
	if cfg.URL == "" {
		s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: origin})
		writeNativeError(w, http.StatusBadRequest, "stream_not_configured", "set a stream URL first")
		return
	}
	synthetic := store.AuditRecord{
		ID:          0,
		Action:      action,
		Result:      store.AuditResultSuccess,
		AuditOrigin: origin,
		CreatedAt:   time.Now().UTC(),
	}
	synthetic.AccountID = account
	status, err := s.sendAuditEvent(ctx, cfg, synthetic)
	delivered := err == nil
	result, errType := "ok", ""
	if !delivered {
		log.Printf("audit stream test failed: %v", err)
		result, errType = "error", "DeliveryFailed"
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, Result: result, ErrorType: errType, AuditOrigin: origin})
	out := map[string]any{"delivered": delivered}
	if status != 0 {
		out["status"] = status
	}
	writeNativeJSON(w, http.StatusOK, out)
}
