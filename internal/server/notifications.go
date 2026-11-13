package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/worlddrknss/citadel/internal/config"
	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// Notifications: account-scoped channels (a signed webhook, a Slack incoming
// webhook, or email through the deployment's SMTP server) subscribe to typed
// events. Features raise an event with s.notify, which queues one delivery
// per subscribed channel in a durable outbox; a background worker on every
// replica claims due deliveries (FOR UPDATE SKIP LOCKED in PostgreSQL) and
// sends them, retrying with exponential backoff and dead-lettering after
// notificationMaxAttempts. The outbox is also each channel's delivery log.

// Notification event types. To add one, add a constant and an entry to
// notificationEvents; channels can then subscribe to it and features can
// raise it with s.notify.
const (
	EventAgentApprovalRequested = "agent.approval_requested"
	EventAgentAccessDecided     = "agent.access_decided"
	EventAgentSuspended         = "agent.suspended"
	EventAgentAnomaly           = "agent.anomaly"
	EventSecurityKillSwitch     = "security.kill_switch"
	// EventTest is sent by "Send test"; channels always accept it.
	EventTest = "test"
)

// notificationEventSpec describes an event type for the console and for
// rendering Slack and email messages.
type notificationEventSpec struct {
	Type        string `json:"type"`
	Title       string `json:"title"`
	Description string `json:"description"`
	// Severity is info, warning or critical.
	Severity string `json:"severity"`
}

var notificationEvents = []notificationEventSpec{
	{EventAgentApprovalRequested, "Agent approval requested", "An agent asked for access that needs a human's approval.", "warning"},
	{EventAgentAccessDecided, "Agent access decided", "Someone approved or denied an agent's access request.", "info"},
	{EventAgentSuspended, "Agent suspended", "An agent was suspended, by a person or automatically.", "warning"},
	{EventAgentAnomaly, "Agent anomaly", "An agent behaved unusually: a new host, off-hours use, a rate spike or repeated denials.", "warning"},
	{EventSecurityKillSwitch, "Kill switch used", "Every agent in the account was suspended with the kill switch.", "critical"},
	{EventTest, "Test notification", "Sent when you use Send test.", "info"},
}

func notificationEvent(t string) (notificationEventSpec, bool) {
	for _, e := range notificationEvents {
		if e.Type == t {
			return e, true
		}
	}
	return notificationEventSpec{}, false
}

const (
	notificationTick        = 5 * time.Second
	notificationBatch       = 32
	notificationParallel    = 8
	notificationLease       = 5 * time.Minute
	notificationMaxAttempts = 10
	notificationBaseBackoff = 30 * time.Second
	notificationMaxBackoff  = time.Hour
	notificationTimeout     = 15 * time.Second
	notificationSMTPTimeout = 30 * time.Second
	notificationPayloadMax  = 64 << 10
	notificationRetention   = 30 * 24 * time.Hour
)

// notificationRuntime is the notification worker's state. The zero value is
// ready to use.
type notificationRuntime struct {
	// running is set while a delivery round runs in this process.
	running atomic.Bool
	// client replaces the webhook/Slack HTTP client (tests).
	client *http.Client
	// smtpRootCAs replaces the system roots for the SMTP server (tests).
	smtpRootCAs *x509.CertPool
	// backoff replaces notificationBackoff (tests).
	backoff func(attempts int) time.Duration
	// done, when set, is signalled after every delivery round (tests).
	mu   sync.Mutex
	done chan struct{}
}

// notify raises event for accountID: it queues a delivery for every enabled
// channel in the account subscribed to event. payload is the event's data,
// marshalled to a JSON object; it must never contain secret values, which
// would be stored in the outbox and sent to third parties. Callers should
// log a failure and carry on: a notification is never a reason to fail the
// operation that raised it.
func (s *Server) notify(ctx context.Context, accountID, event string, payload any) error {
	if _, ok := notificationEvent(event); !ok {
		return fmt.Errorf("unknown notification event %q", event)
	}
	if accountID == "" {
		return errors.New("notify: account is required")
	}
	body, err := notificationPayload(payload)
	if err != nil {
		return err
	}
	n, err := s.store.EnqueueNotification(ctx, store.NotificationEnqueue{
		AccountID: accountID, EventID: newNotificationEventID(), EventType: event, Payload: body,
	})
	if err != nil {
		return err
	}
	if n > 0 {
		s.kickNotifications()
	}
	return nil
}

func newNotificationEventID() string { return "evt_" + cryptoutil.RandomHex(12) }

// notificationPayload marshals payload as a JSON object (nil is {}).
func notificationPayload(payload any) (string, error) {
	if payload == nil {
		return "{}", nil
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("notify: payload: %w", err)
	}
	if len(b) == 0 || b[0] != '{' {
		return "", errors.New("notify: payload must be a JSON object")
	}
	if len(b) > notificationPayloadMax {
		return "", errors.New("notify: payload is too large")
	}
	return string(b), nil
}

// kickNotifications starts a delivery round now unless one is running. It
// does nothing in servers built without New (tests drive rounds directly).
func (s *Server) kickNotifications() {
	if s.jobs == nil || !s.notif.running.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer s.notif.running.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), notificationLease)
		defer cancel()
		s.runNotificationRounds(ctx)
	}()
}

// notificationJob is the periodic delivery job.
func (s *Server) notificationJob(ctx context.Context) error {
	if !s.notif.running.CompareAndSwap(false, true) {
		return nil // a kicked round is already running
	}
	defer s.notif.running.Store(false)
	s.runNotificationRounds(ctx)
	return nil
}

// runNotificationRounds drains due deliveries, a batch at a time, for at
// most a few batches per call.
func (s *Server) runNotificationRounds(ctx context.Context) {
	for i := 0; i < 4; i++ {
		if n := s.deliverNotifications(ctx); n < notificationBatch {
			return
		}
	}
}

// notificationPurgeJob drops finished deliveries older than the retention.
func (s *Server) notificationPurgeJob(ctx context.Context) error {
	_, err := s.store.PurgeNotificationDeliveries(ctx, time.Now().Add(-notificationRetention))
	return err
}

// deliverNotifications runs one round: claim a batch and send it. It
// returns how many deliveries it claimed.
func (s *Server) deliverNotifications(ctx context.Context) int {
	defer s.signalNotificationRound()
	items, err := s.store.ClaimNotificationDeliveries(ctx, notificationBatch, notificationLease)
	if err != nil {
		log.Printf("notifications: claim failed: %v", err)
		return 0
	}
	type key struct{ account, id string }
	var mu sync.Mutex
	channels := map[key]*store.NotificationChannel{}
	channel := func(d store.NotificationDelivery) (*store.NotificationChannel, error) {
		mu.Lock()
		defer mu.Unlock()
		k := key{d.AccountID, d.ChannelID}
		if ch, ok := channels[k]; ok {
			return ch, nil
		}
		ch, err := s.store.GetNotificationChannel(ctx, d.AccountID, d.ChannelID)
		if errors.Is(err, store.ErrNotificationChannelNotFound) {
			channels[k] = nil
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		channels[k] = &ch
		return &ch, nil
	}
	sem := make(chan struct{}, notificationParallel)
	var wg sync.WaitGroup
	for _, d := range items {
		ch, err := channel(d)
		if err != nil {
			log.Printf("notifications: channel read failed delivery=%d: %v", d.ID, err)
			continue // the lease expires and the delivery is retried
		}
		if ch == nil {
			continue // deleted with its deliveries
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(d store.NotificationDelivery, ch store.NotificationChannel) {
			defer func() { <-sem; wg.Done() }()
			s.deliverNotification(ctx, ch, d)
		}(d, *ch)
	}
	wg.Wait()
	return len(items)
}

func (s *Server) signalNotificationRound() {
	s.notif.mu.Lock()
	done := s.notif.done
	s.notif.mu.Unlock()
	if done != nil {
		select {
		case done <- struct{}{}:
		default:
		}
	}
}

// notificationBackoff is the wait after the given number of failed
// attempts: 30s, 1m, 2m... up to an hour.
func notificationBackoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	b := notificationBaseBackoff << min(attempts-1, 20)
	if b > notificationMaxBackoff || b <= 0 {
		return notificationMaxBackoff
	}
	return b
}

func (s *Server) deliverNotification(ctx context.Context, ch store.NotificationChannel, d store.NotificationDelivery) {
	var status int
	var err error
	if !ch.Enabled && d.EventType != EventTest {
		err = errors.New("the channel was disabled before delivery")
		if rerr := s.store.RetryNotificationDelivery(ctx, d.ID, d.LeaseToken, time.Now(), err.Error(), 0, true); rerr != nil {
			log.Printf("notifications: bookkeeping failed delivery=%d: %v", d.ID, rerr)
		}
		return
	}
	switch ch.Type {
	case store.NotificationWebhook:
		status, err = s.sendNotificationWebhook(ctx, ch, d)
	case store.NotificationSlack:
		status, err = s.sendNotificationSlack(ctx, ch, d)
	case store.NotificationEmail:
		err = s.sendNotificationEmail(ctx, ch, d)
	default:
		err = errors.New("unknown channel type")
	}
	if err == nil {
		if cerr := s.store.CompleteNotificationDelivery(ctx, d.ID, d.LeaseToken, status); cerr != nil {
			log.Printf("notifications: bookkeeping failed delivery=%d: %v", d.ID, cerr)
		}
		return
	}
	attempts := d.Attempts + 1
	dead := attempts >= notificationMaxAttempts
	log.Printf("notifications: delivery failed delivery=%d channel=%s type=%s attempt=%d dead=%t: %v",
		d.ID, ch.ID, ch.Type, attempts, dead, err)
	backoff := notificationBackoff
	if s.notif.backoff != nil {
		backoff = s.notif.backoff
	}
	if rerr := s.store.RetryNotificationDelivery(ctx, d.ID, d.LeaseToken, time.Now().Add(backoff(attempts)), err.Error(), status, dead); rerr != nil {
		log.Printf("notifications: bookkeeping failed delivery=%d: %v", d.ID, rerr)
	}
}

// ---- messages ----------------------------------------------------------------

// notificationEnvelope is the JSON body of a webhook delivery.
type notificationEnvelope struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	AccountID string          `json:"accountId"`
	CreatedAt string          `json:"createdAt"`
	Data      json.RawMessage `json:"data"`
}

func envelopeFor(d store.NotificationDelivery) ([]byte, error) {
	data := json.RawMessage(d.Payload)
	if !json.Valid(data) {
		data = json.RawMessage("{}")
	}
	return json.Marshal(notificationEnvelope{
		ID: d.EventID, Type: d.EventType, AccountID: d.AccountID,
		CreatedAt: d.CreatedAt.UTC().Format(time.RFC3339), Data: data,
	})
}

// notificationSummary renders an event for people: a title, an optional
// summary line (the payload's "summary" or "message"), and the payload's
// other scalar fields, sorted by name.
type notificationSummary struct {
	Title    string
	Severity string
	Summary  string
	Fields   [][2]string
}

func summarize(d store.NotificationDelivery) notificationSummary {
	spec, ok := notificationEvent(d.EventType)
	if !ok {
		spec = notificationEventSpec{Title: d.EventType, Severity: "info"}
	}
	out := notificationSummary{Title: spec.Title, Severity: spec.Severity}
	var data map[string]any
	_ = json.Unmarshal([]byte(d.Payload), &data)
	for _, k := range []string{"summary", "message"} {
		if v, ok := data[k].(string); ok && out.Summary == "" {
			out.Summary = oneLine(v, 500)
			delete(data, k)
		}
	}
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		var v string
		switch x := data[k].(type) {
		case string:
			v = x
		case float64:
			v = strconv.FormatFloat(x, 'f', -1, 64)
		case bool:
			v = strconv.FormatBool(x)
		default:
			continue
		}
		if len(out.Fields) == 12 {
			break
		}
		out.Fields = append(out.Fields, [2]string{oneLine(k, 64), oneLine(v, 200)})
	}
	return out
}

// oneLine strips control characters (so nothing can break out of a header
// or a Slack line) and truncates to max bytes.
func oneLine(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > max {
		cut := max
		for cut > 0 && (s[cut]&0xC0) == 0x80 {
			cut--
		}
		s = s[:cut] + "…"
	}
	return strings.TrimSpace(s)
}

// ---- webhook -----------------------------------------------------------------

const (
	notificationEventHdr    = "X-Citadel-Event"
	notificationEventIDHdr  = "X-Citadel-Event-Id"
	notificationDeliveryHdr = "X-Citadel-Delivery"
)

func (s *Server) notificationHTTPClient() *http.Client {
	if s.notif.client != nil {
		return s.notif.client
	}
	return newGuardedHTTPClient(nil, notificationTimeout)
}

// notificationSignature is the X-Citadel-Signature value for body sent at
// ts: "t=<unix>,v1=<hex HMAC-SHA256(secret, "<unix>.<body>")>".
func notificationSignature(secret string, ts int64, body []byte) string {
	t := strconv.FormatInt(ts, 10)
	return "t=" + t + "," + signWebhook(secret, t, body)
}

func (s *Server) sendNotificationWebhook(ctx context.Context, ch store.NotificationChannel, d store.NotificationDelivery) (int, error) {
	if err := validateStreamURL(ch.URL); err != nil {
		return 0, err
	}
	if len(ch.SecretSealed) == 0 {
		return 0, errors.New("the channel has no signing secret")
	}
	secret, err := s.openNotificationSecret(ch, "signing-secret", ch.SecretSealed)
	if err != nil {
		return 0, errors.New("the signing secret could not be decrypted")
	}
	body, err := envelopeFor(d)
	if err != nil {
		return 0, err
	}
	return s.postNotification(ctx, ch.URL, body, map[string]string{
		"X-Citadel-Signature":   notificationSignature(secret, time.Now().Unix(), body),
		notificationEventHdr:    d.EventType,
		notificationEventIDHdr:  d.EventID,
		notificationDeliveryHdr: strconv.FormatInt(d.ID, 10),
	})
}

// postNotification POSTs a JSON body. Errors never include the URL (a Slack
// URL is a credential).
func (s *Server) postNotification(ctx context.Context, target string, body []byte, headers map[string]string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, notificationTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return 0, errors.New("invalid destination URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", AppName+"-notifications/1")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.notificationHTTPClient().Do(req)
	if err != nil {
		return 0, notificationNetError(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, fmt.Errorf("the destination returned HTTP %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

// notificationNetError maps a client error to a fixed, URL-free message.
func notificationNetError(err error) error {
	switch {
	case errors.Is(err, errSSRFBlocked) || strings.Contains(err.Error(), errSSRFBlocked.Error()):
		return errors.New("the destination address is not allowed (loopback, link-local or metadata)")
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "Client.Timeout"):
		return errors.New("the destination did not respond in time")
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return errors.New("the destination host name could not be resolved")
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return errors.New("the destination's TLS certificate is not trusted")
	}
	return errors.New("the destination could not be reached")
}

// ---- slack -------------------------------------------------------------------

// slackHost is the only host Slack incoming webhooks are sent to.
const slackHost = "hooks.slack.com"

// validateSlackURL accepts https://hooks.slack.com/<path> only.
func validateSlackURL(raw string) error {
	if err := validateStreamURL(raw); err != nil {
		return err
	}
	u, _ := url.Parse(raw)
	if !strings.EqualFold(u.Hostname(), slackHost) || u.Port() != "" {
		return errors.New("url must be a Slack incoming webhook URL (https://hooks.slack.com/...)")
	}
	if strings.Trim(u.Path, "/") == "" {
		return errors.New("url must be a Slack incoming webhook URL (https://hooks.slack.com/...)")
	}
	return nil
}

// slackURLHint shows a Slack URL without its last path segment (the secret).
func slackURLHint(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return slackHost + "/…"
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) <= 1 {
		return slackHost + "/…"
	}
	return slackHost + "/" + strings.Join(parts[:len(parts)-1], "/") + "/…"
}

// slackEscape escapes Slack mrkdwn control characters.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func slackText(d store.NotificationDelivery) string {
	sum := summarize(d)
	icon := ":information_source:"
	switch sum.Severity {
	case "warning":
		icon = ":warning:"
	case "critical":
		icon = ":rotating_light:"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s *%s*", icon, slackEscape(sum.Title))
	if sum.Summary != "" {
		b.WriteString("\n" + slackEscape(sum.Summary))
	}
	for _, f := range sum.Fields {
		fmt.Fprintf(&b, "\n• %s: `%s`", slackEscape(f[0]), slackEscape(strings.ReplaceAll(f[1], "`", "'")))
	}
	fmt.Fprintf(&b, "\nAccount `%s` · %s · `%s`", slackEscape(d.AccountID), slackEscape(d.EventType), slackEscape(d.EventID))
	return b.String()
}

func (s *Server) sendNotificationSlack(ctx context.Context, ch store.NotificationChannel, d store.NotificationDelivery) (int, error) {
	if len(ch.URLSealed) == 0 {
		return 0, errors.New("the channel has no Slack URL")
	}
	target, err := s.openNotificationSecret(ch, "slack-url", ch.URLSealed)
	if err != nil {
		return 0, errors.New("the Slack URL could not be decrypted")
	}
	if err := validateSlackURL(target); err != nil {
		return 0, errors.New("the stored Slack URL is not valid")
	}
	body, _ := json.Marshal(map[string]string{"text": slackText(d)})
	return s.postNotification(ctx, target, body, nil)
}

// ---- email -------------------------------------------------------------------

// maxNotificationRecipients bounds an email channel's recipient list.
const maxNotificationRecipients = 20

func emailBody(d store.NotificationDelivery) (subject, text string) {
	sum := summarize(d)
	subject = oneLine("["+AppName+"] "+sum.Title, 200)
	var b strings.Builder
	b.WriteString(sum.Title + "\n")
	if sum.Summary != "" {
		b.WriteString("\n" + sum.Summary + "\n")
	}
	if len(sum.Fields) > 0 {
		b.WriteString("\n")
		for _, f := range sum.Fields {
			b.WriteString(f[0] + ": " + f[1] + "\n")
		}
	}
	fmt.Fprintf(&b, "\nAccount: %s\nEvent: %s (%s)\nTime: %s\n", d.AccountID, d.EventType, d.EventID, d.CreatedAt.UTC().Format(time.RFC1123))
	b.WriteString("\nYou receive this because an administrator subscribed this address to " + AppName + " notifications.\n")
	return subject, b.String()
}

// buildEmail renders an RFC 5322 message with a quoted-printable body.
func buildEmail(from string, to []string, d store.NotificationDelivery, host string) ([]byte, error) {
	subject, text := emailBody(d)
	var b bytes.Buffer
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", from)
	h("To", strings.Join(to, ", "))
	h("Subject", mime.QEncoding.Encode("utf-8", subject))
	h("Date", time.Now().UTC().Format(time.RFC1123Z))
	h("Message-ID", "<"+d.EventID+"."+strconv.FormatInt(d.ID, 10)+"@"+host+">")
	h("MIME-Version", "1.0")
	h("Content-Type", "text/plain; charset=utf-8")
	h("Content-Transfer-Encoding", "quoted-printable")
	h("Auto-Submitted", "auto-generated")
	h("X-Citadel-Event", d.EventType)
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	if _, err := qp.Write([]byte(strings.ReplaceAll(text, "\n", "\r\n"))); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (s *Server) sendNotificationEmail(ctx context.Context, ch store.NotificationChannel, d store.NotificationDelivery) error {
	cfg := s.cfg.SMTP
	if !cfg.Enabled() {
		return errors.New("email is not configured on this server (KMS_SMTP_HOST)")
	}
	if len(ch.Recipients) == 0 {
		return errors.New("the channel has no recipients")
	}
	from, err := mail.ParseAddress(cfg.From)
	if err != nil {
		return errors.New("the configured sender address is not valid")
	}
	msg, err := buildEmail(cfg.From, ch.Recipients, d, messageIDHost(from.Address))
	if err != nil {
		return err
	}
	return s.smtpSend(ctx, cfg, from.Address, ch.Recipients, msg)
}

func messageIDHost(addr string) string {
	if _, host, ok := strings.Cut(addr, "@"); ok && host != "" {
		return host
	}
	return "citadel.invalid"
}

// smtpSend delivers msg over TLS (implicit, or STARTTLS which must be
// offered). It authenticates only over TLS: net/smtp's PLAIN auth refuses
// an unencrypted connection, and there is no plaintext mode to begin with.
func (s *Server) smtpSend(ctx context.Context, cfg config.SMTPConfig, from string, to []string, msg []byte) (err error) {
	ctx, cancel := context.WithTimeout(ctx, notificationSMTPTimeout)
	defer cancel()
	tlsCfg := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12, RootCAs: s.notif.smtpRootCAs}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return errors.New("smtp: could not connect to the mail server")
	}
	deadline, _ := ctx.Deadline()
	_ = raw.SetDeadline(deadline)
	conn := raw
	if cfg.TLS == config.SMTPImplicitTLS {
		tc := tls.Client(raw, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return smtpTLSError(err)
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return smtpError("greeting", err)
	}
	defer c.Close()
	if err := c.Hello(messageIDHost(from)); err != nil {
		return smtpError("EHLO", err)
	}
	if cfg.TLS == config.SMTPStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("smtp: the mail server does not offer STARTTLS; refusing to send in plaintext")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return smtpTLSError(err)
		}
	}
	if cfg.Username != "" {
		pw, err := cfg.SMTPPassword()
		if err != nil {
			return errors.New("smtp: the password could not be read")
		}
		if ok, _ := c.Extension("AUTH"); !ok {
			return errors.New("smtp: the mail server does not offer authentication")
		}
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, pw, cfg.Host)); err != nil {
			return errors.New("smtp: authentication failed")
		}
	}
	if err := c.Mail(from); err != nil {
		return smtpError("MAIL FROM", err)
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return smtpError("RCPT TO", err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return smtpError("DATA", err)
	}
	if _, err := w.Write(msg); err != nil {
		return smtpError("DATA", err)
	}
	if err := w.Close(); err != nil {
		return smtpError("DATA", err)
	}
	_ = c.Quit()
	return nil
}

func smtpTLSError(err error) error {
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return errors.New("smtp: the mail server's TLS certificate is not trusted")
	}
	return errors.New("smtp: the TLS handshake failed")
}

// smtpError keeps an SMTP reply code (never the server's free text, which
// can echo addresses or credentials) for diagnosis.
func smtpError(stage string, err error) error {
	msg := err.Error()
	if len(msg) >= 3 && msg[0] >= '2' && msg[0] <= '5' && msg[1] >= '0' && msg[1] <= '9' && msg[2] >= '0' && msg[2] <= '9' {
		return fmt.Errorf("smtp: %s refused (%s)", stage, msg[:3])
	}
	return fmt.Errorf("smtp: %s failed", stage)
}

// ---- secrets -----------------------------------------------------------------

func (s *Server) notificationSealKey() ([]byte, error) {
	switch {
	case len(s.deploymentSecret()) > 0:
		return cryptoutil.DeriveNotificationSealKey(s.deploymentSecret()), nil
	case len(s.cfg.AuditHMACKey) > 0:
		return cryptoutil.DeriveNotificationSealKey(s.cfg.AuditHMACKey), nil
	}
	return nil, errors.New("no key is configured to seal notification secrets")
}

// notificationAAD binds a sealed value to its account, channel and purpose,
// so it can't be moved to another channel or field.
func notificationAAD(ch store.NotificationChannel, purpose string) []byte {
	return []byte("citadel/notification/v1|" + ch.AccountID + "|" + ch.ID + "|" + purpose)
}

func (s *Server) sealNotificationSecret(ch store.NotificationChannel, purpose, value string) ([]byte, error) {
	key, err := s.notificationSealKey()
	if err != nil {
		return nil, err
	}
	return cryptoutil.GCMSeal(key, []byte(value), notificationAAD(ch, purpose))
}

func (s *Server) openNotificationSecret(ch store.NotificationChannel, purpose string, sealed []byte) (string, error) {
	key, err := s.notificationSealKey()
	if err != nil {
		return "", err
	}
	pt, err := cryptoutil.GCMOpen(key, sealed, notificationAAD(ch, purpose))
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// newNotificationSigningSecret returns a fresh signing secret and its sealed
// form for ch.
func (s *Server) newNotificationSigningSecret(ch store.NotificationChannel) (string, []byte, error) {
	secret := "whsec_" + cryptoutil.RandomHex(32)
	sealed, err := s.sealNotificationSecret(ch, "signing-secret", secret)
	if err != nil {
		return "", nil, err
	}
	return secret, sealed, nil
}
