package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// registerNotificationRoutes adds the notification channel API and the
// delivery and purge jobs. Every operation needs the admin role in the
// caller's account.
func (s *Server) registerNotificationRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/notifications/channels", s.handleV1ListNotificationChannels)
	mux.HandleFunc("POST /v1/notifications/channels", s.handleV1CreateNotificationChannel)
	mux.HandleFunc("POST /v1/notifications/channels/update", s.handleV1UpdateNotificationChannel)
	mux.HandleFunc("DELETE /v1/notifications/channels", s.handleV1DeleteNotificationChannel)
	mux.HandleFunc("POST /v1/notifications/channels/test", s.handleV1TestNotificationChannel)
	mux.HandleFunc("POST /v1/notifications/channels/signing-secret", s.handleV1RotateNotificationSecret)
	mux.HandleFunc("GET /v1/notifications/deliveries", s.handleV1ListNotificationDeliveries)
	mux.HandleFunc("POST /v1/notifications/deliveries/retry", s.handleV1RetryNotificationDelivery)
	s.jobs.Every("notification-delivery", notificationTick, s.notificationJob)
	s.jobs.Every("notification-purge", time.Hour, s.notificationPurgeJob)
}

const (
	maxNotificationChannels = 50
	maxNotificationNameLen  = 64
	maxNotificationLog      = 200
)

type notificationChannelJSON struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Type             string   `json:"type"`
	Enabled          bool     `json:"enabled"`
	Events           []string `json:"events"`
	URL              string   `json:"url,omitempty"`
	URLHint          string   `json:"urlHint,omitempty"`
	Recipients       []string `json:"recipients,omitempty"`
	HasSigningSecret bool     `json:"hasSigningSecret"`
	CreatedAt        string   `json:"createdAt"`
	CreatedBy        string   `json:"createdBy"`
	UpdatedAt        string   `json:"updatedAt"`
	UpdatedBy        string   `json:"updatedBy"`
}

func toNotificationChannelJSON(ch store.NotificationChannel) notificationChannelJSON {
	events := ch.Events
	if events == nil {
		events = []string{}
	}
	return notificationChannelJSON{
		ID: ch.ID, Name: ch.Name, Type: ch.Type, Enabled: ch.Enabled, Events: events, URL: ch.URL, URLHint: ch.URLHint,
		Recipients: ch.Recipients, HasSigningSecret: len(ch.SecretSealed) > 0,
		CreatedAt: ch.CreatedAt.UTC().Format(time.RFC3339), CreatedBy: ch.CreatedBy,
		UpdatedAt: ch.UpdatedAt.UTC().Format(time.RFC3339), UpdatedBy: ch.UpdatedBy,
	}
}

type notificationDeliveryJSON struct {
	ID            int64           `json:"id"`
	ChannelID     string          `json:"channelId"`
	EventID       string          `json:"eventId"`
	EventType     string          `json:"eventType"`
	Status        string          `json:"status"`
	Attempts      int             `json:"attempts"`
	LastError     string          `json:"lastError,omitempty"`
	StatusCode    int             `json:"statusCode,omitempty"`
	CreatedAt     string          `json:"createdAt"`
	NextAttemptAt string          `json:"nextAttemptAt,omitempty"`
	LastAttemptAt string          `json:"lastAttemptAt,omitempty"`
	DeliveredAt   string          `json:"deliveredAt,omitempty"`
	Data          json.RawMessage `json:"data"`
}

func optTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func toNotificationDeliveryJSON(d store.NotificationDelivery) notificationDeliveryJSON {
	data := json.RawMessage(d.Payload)
	if !json.Valid(data) {
		data = json.RawMessage("{}")
	}
	out := notificationDeliveryJSON{
		ID: d.ID, ChannelID: d.ChannelID, EventID: d.EventID, EventType: d.EventType, Status: d.Status, Attempts: d.Attempts,
		LastError: d.LastError, StatusCode: d.StatusCode, CreatedAt: d.CreatedAt.UTC().Format(time.RFC3339),
		LastAttemptAt: optTime(d.LastAttemptAt), DeliveredAt: optTime(d.DeliveredAt), Data: data,
	}
	if d.Status == store.NotificationPending {
		out.NextAttemptAt = optTime(d.NextAttemptAt)
	}
	return out
}

// notificationInputError is a validation failure whose text is safe to
// return.
type notificationInputError struct{ code, msg string }

func (e notificationInputError) Error() string { return e.msg }

func badNotification(msg string) error { return notificationInputError{"invalid_request", msg} }

func validNotificationName(name string) error {
	if name == "" || len(name) > maxNotificationNameLen {
		return badNotification(fmt.Sprintf("name must be 1 to %d characters", maxNotificationNameLen))
	}
	for _, r := range name {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(" ._-", r)) {
			return badNotification("name may contain letters, digits, spaces, '.', '_' and '-'")
		}
	}
	return nil
}

// normalizeNotificationEvents checks event types, drops duplicates and the
// test event (always delivered), and keeps the catalog's order.
func normalizeNotificationEvents(in []string) ([]string, error) {
	want := map[string]bool{}
	for _, e := range in {
		e = strings.TrimSpace(e)
		if _, ok := notificationEvent(e); !ok {
			return nil, badNotification(fmt.Sprintf("unknown event type %q", oneLine(e, 64)))
		}
		want[e] = true
	}
	out := []string{}
	for _, spec := range notificationEvents {
		if want[spec.Type] && spec.Type != EventTest {
			out = append(out, spec.Type)
		}
	}
	return out, nil
}

func normalizeRecipients(in []string) ([]string, error) {
	var out []string
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		a, err := mail.ParseAddress(raw)
		if err != nil || strings.ContainsAny(raw, "\r\n") || a.Address != raw && a.Name == "" {
			return nil, badNotification(fmt.Sprintf("%q is not an email address", oneLine(raw, 254)))
		}
		if len(a.Address) > 254 {
			return nil, badNotification("email addresses must be at most 254 characters")
		}
		if !slices.Contains(out, a.Address) {
			out = append(out, a.Address)
		}
	}
	if len(out) == 0 {
		return nil, badNotification("add at least one recipient")
	}
	if len(out) > maxNotificationRecipients {
		return nil, badNotification(fmt.Sprintf("at most %d recipients", maxNotificationRecipients))
	}
	return out, nil
}

// applyNotificationTarget validates and stores a channel's destination: the
// webhook URL, the (sealed) Slack URL, or the recipients.
func (s *Server) applyNotificationTarget(ch *store.NotificationChannel, url *string, recipients []string, creating bool) error {
	switch ch.Type {
	case store.NotificationWebhook:
		if url == nil {
			if creating {
				return badNotification("url is required")
			}
			return nil
		}
		u := strings.TrimSpace(*url)
		if err := validateStreamURL(u); err != nil {
			return badNotification(err.Error())
		}
		ch.URL = u
	case store.NotificationSlack:
		if url == nil {
			if creating {
				return badNotification("url is required")
			}
			return nil
		}
		u := strings.TrimSpace(*url)
		if err := validateSlackURL(u); err != nil {
			return badNotification(err.Error())
		}
		sealed, err := s.sealNotificationSecret(*ch, "slack-url", u)
		if err != nil {
			return err
		}
		ch.URLSealed, ch.URLHint = sealed, slackURLHint(u)
	case store.NotificationEmail:
		if url != nil && strings.TrimSpace(*url) != "" {
			return badNotification("email channels take recipients, not a url")
		}
		if recipients == nil {
			if creating {
				return badNotification("add at least one recipient")
			}
			return nil
		}
		rcpts, err := normalizeRecipients(recipients)
		if err != nil {
			return err
		}
		ch.Recipients = rcpts
	}
	if ch.Type != store.NotificationEmail && recipients != nil {
		return badNotification("only email channels take recipients")
	}
	return nil
}

// notificationAdmin authenticates an account admin.
func (s *Server) notificationAdmin(w http.ResponseWriter, r *http.Request) (*uiSession, context.Context, string, bool) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return nil, nil, "", false
	}
	return sess, ctx, s.auditAccount(ctx), true
}

// notificationFail writes an error and its audit event.
func (s *Server) notificationFail(w http.ResponseWriter, r *http.Request, ctx context.Context, action, resource string, err error) {
	origin := s.auditOrigin(r)
	origin.Resource = resource
	var in notificationInputError
	switch {
	case errors.As(err, &in):
		s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: origin})
		writeNativeError(w, http.StatusBadRequest, in.code, in.msg)
	case errors.Is(err, store.ErrNotificationChannelNotFound):
		s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "error", ErrorType: "ResourceNotFoundException", AuditOrigin: origin})
		writeNativeError(w, http.StatusNotFound, "not_found", "notification channel not found")
	case errors.Is(err, store.ErrNotificationDeliveryNotFound):
		s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "error", ErrorType: "ResourceNotFoundException", AuditOrigin: origin})
		writeNativeError(w, http.StatusNotFound, "not_found", "no dead-lettered delivery with this id")
	case errors.Is(err, store.ErrNotificationChannelExists):
		s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "error", ErrorType: "ResourceExistsException", AuditOrigin: origin})
		writeNativeError(w, http.StatusConflict, "already_exists", "a notification channel with this name already exists")
	default:
		log.Printf("notifications: %s failed: %v", action, err)
		s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "error", ErrorType: "InternalFailure", AuditOrigin: origin})
		writeNativeError(w, http.StatusInternalServerError, "notifications_failed", "the notification channel could not be saved")
	}
}

func (s *Server) notificationOK(r *http.Request, ctx context.Context, action, resource string) {
	origin := s.auditOrigin(r)
	origin.Resource = resource
	s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "ok", AuditOrigin: origin})
}

// GET /v1/notifications/channels — admin. The channels, the event catalog,
// and whether email is available on this server.
func (s *Server) handleV1ListNotificationChannels(w http.ResponseWriter, r *http.Request) {
	_, ctx, account, ok := s.notificationAdmin(w, r)
	if !ok {
		return
	}
	list, err := s.store.ListNotificationChannels(ctx, account)
	if err != nil {
		log.Printf("notifications: list failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "notifications_failed", "the notification channels could not be read")
		return
	}
	out := make([]notificationChannelJSON, 0, len(list))
	for _, ch := range list {
		out = append(out, toNotificationChannelJSON(ch))
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{
		"channels": out, "events": notificationEvents, "emailAvailable": s.cfg.SMTP.Enabled(),
	})
}

// POST /v1/notifications/channels — admin. A webhook channel's signing
// secret is generated and returned once.
func (s *Server) handleV1CreateNotificationChannel(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.CreateNotificationChannel"
	sess, ctx, account, ok := s.notificationAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Name       string   `json:"name"`
		Type       string   `json:"type"`
		Enabled    *bool    `json:"enabled"`
		Events     []string `json:"events"`
		URL        *string  `json:"url"`
		Recipients []string `json:"recipients"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		s.notificationFail(w, r, ctx, action, "", badNotification("invalid JSON body"))
		return
	}
	ch := store.NotificationChannel{
		ID: "nch_" + cryptoutil.RandomHex(10), AccountID: account, Name: strings.TrimSpace(req.Name),
		Type: strings.ToLower(strings.TrimSpace(req.Type)), Enabled: req.Enabled == nil || *req.Enabled, CreatedBy: sess.Username,
	}
	if err := validNotificationName(ch.Name); err != nil {
		s.notificationFail(w, r, ctx, action, "", err)
		return
	}
	switch ch.Type {
	case store.NotificationWebhook, store.NotificationSlack:
	case store.NotificationEmail:
		if !s.cfg.SMTP.Enabled() {
			s.notificationFail(w, r, ctx, action, "", notificationInputError{"email_unavailable", "email notifications need an SMTP server configured on Citadel (KMS_SMTP_HOST)"})
			return
		}
	default:
		s.notificationFail(w, r, ctx, action, "", badNotification("type must be webhook, slack or email"))
		return
	}
	events, err := normalizeNotificationEvents(req.Events)
	if err != nil {
		s.notificationFail(w, r, ctx, action, "", err)
		return
	}
	ch.Events = events
	if err := s.applyNotificationTarget(&ch, req.URL, req.Recipients, true); err != nil {
		s.notificationFail(w, r, ctx, action, "", err)
		return
	}
	existing, err := s.store.ListNotificationChannels(ctx, account)
	if err != nil {
		s.notificationFail(w, r, ctx, action, "", err)
		return
	}
	if len(existing) >= maxNotificationChannels {
		s.notificationFail(w, r, ctx, action, "", notificationInputError{"limit_exceeded", fmt.Sprintf("an account can have at most %d notification channels", maxNotificationChannels)})
		return
	}
	var secret string
	if ch.Type == store.NotificationWebhook {
		if secret, ch.SecretSealed, err = s.newNotificationSigningSecret(ch); err != nil {
			s.notificationFail(w, r, ctx, action, "", err)
			return
		}
	}
	if err := s.store.CreateNotificationChannel(ctx, ch); err != nil {
		s.notificationFail(w, r, ctx, action, ch.ID, err)
		return
	}
	created, err := s.store.GetNotificationChannel(ctx, account, ch.ID)
	if err != nil {
		created = ch
	}
	s.notificationOK(r, ctx, action, ch.ID)
	out := map[string]any{"channel": toNotificationChannelJSON(created)}
	if secret != "" {
		out["signingSecret"] = secret
	}
	writeNativeJSON(w, http.StatusCreated, out)
}

// POST /v1/notifications/channels/update — admin. Omitted members keep
// their value; a Slack channel's url is write-only and kept when omitted.
func (s *Server) handleV1UpdateNotificationChannel(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.UpdateNotificationChannel"
	sess, ctx, account, ok := s.notificationAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		ID         string   `json:"id"`
		Name       *string  `json:"name"`
		Enabled    *bool    `json:"enabled"`
		Events     []string `json:"events"`
		URL        *string  `json:"url"`
		Recipients []string `json:"recipients"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		s.notificationFail(w, r, ctx, action, "", badNotification("invalid JSON body"))
		return
	}
	ch, err := s.store.GetNotificationChannel(ctx, account, strings.TrimSpace(req.ID))
	if err != nil {
		s.notificationFail(w, r, ctx, action, req.ID, err)
		return
	}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if err := validNotificationName(name); err != nil {
			s.notificationFail(w, r, ctx, action, ch.ID, err)
			return
		}
		ch.Name = name
	}
	if req.Enabled != nil {
		ch.Enabled = *req.Enabled
	}
	if req.Events != nil {
		if ch.Events, err = normalizeNotificationEvents(req.Events); err != nil {
			s.notificationFail(w, r, ctx, action, ch.ID, err)
			return
		}
	}
	if err := s.applyNotificationTarget(&ch, req.URL, req.Recipients, false); err != nil {
		s.notificationFail(w, r, ctx, action, ch.ID, err)
		return
	}
	ch.UpdatedBy = sess.Username
	if err := s.store.UpdateNotificationChannel(ctx, ch); err != nil {
		s.notificationFail(w, r, ctx, action, ch.ID, err)
		return
	}
	if updated, err := s.store.GetNotificationChannel(ctx, account, ch.ID); err == nil {
		ch = updated
	}
	s.notificationOK(r, ctx, action, ch.ID)
	writeNativeJSON(w, http.StatusOK, map[string]any{"channel": toNotificationChannelJSON(ch)})
}

// DELETE /v1/notifications/channels?id= — admin. Its delivery log goes too.
func (s *Server) handleV1DeleteNotificationChannel(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.DeleteNotificationChannel"
	_, ctx, account, ok := s.notificationAdmin(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if err := s.store.DeleteNotificationChannel(ctx, account, id); err != nil {
		s.notificationFail(w, r, ctx, action, id, err)
		return
	}
	s.notificationOK(r, ctx, action, id)
	writeNativeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// POST /v1/notifications/channels/test — admin. Queues a test event for the
// channel (even a disabled one) and starts delivery now. The outcome shows
// in the delivery log.
func (s *Server) handleV1TestNotificationChannel(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.TestNotificationChannel"
	sess, ctx, account, ok := s.notificationAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		s.notificationFail(w, r, ctx, action, "", badNotification("invalid JSON body"))
		return
	}
	ch, err := s.store.GetNotificationChannel(ctx, account, strings.TrimSpace(req.ID))
	if err != nil {
		s.notificationFail(w, r, ctx, action, req.ID, err)
		return
	}
	payload, _ := notificationPayload(map[string]string{
		"summary":     "This is a test notification from " + AppName + ". If you can read it, the channel works.",
		"channel":     ch.Name,
		"requestedBy": sess.Username,
	})
	eventID := newNotificationEventID()
	if _, err := s.store.EnqueueNotification(ctx, store.NotificationEnqueue{
		AccountID: account, EventID: eventID, EventType: EventTest, Payload: payload, ChannelID: ch.ID,
	}); err != nil {
		s.notificationFail(w, r, ctx, action, ch.ID, err)
		return
	}
	s.notificationOK(r, ctx, action, ch.ID)
	s.kickNotifications()
	writeNativeJSON(w, http.StatusAccepted, map[string]any{"queued": true, "eventId": eventID})
}

// POST /v1/notifications/channels/signing-secret — admin. Replaces a webhook
// channel's signing secret and returns the new one once.
func (s *Server) handleV1RotateNotificationSecret(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.RotateNotificationSigningSecret"
	sess, ctx, account, ok := s.notificationAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		s.notificationFail(w, r, ctx, action, "", badNotification("invalid JSON body"))
		return
	}
	ch, err := s.store.GetNotificationChannel(ctx, account, strings.TrimSpace(req.ID))
	if err != nil {
		s.notificationFail(w, r, ctx, action, req.ID, err)
		return
	}
	if ch.Type != store.NotificationWebhook {
		s.notificationFail(w, r, ctx, action, ch.ID, badNotification("only webhook channels have a signing secret"))
		return
	}
	secret, sealed, err := s.newNotificationSigningSecret(ch)
	if err != nil {
		s.notificationFail(w, r, ctx, action, ch.ID, err)
		return
	}
	ch.SecretSealed, ch.UpdatedBy = sealed, sess.Username
	if err := s.store.UpdateNotificationChannel(ctx, ch); err != nil {
		s.notificationFail(w, r, ctx, action, ch.ID, err)
		return
	}
	if updated, err := s.store.GetNotificationChannel(ctx, account, ch.ID); err == nil {
		ch = updated
	}
	s.notificationOK(r, ctx, action, ch.ID)
	writeNativeJSON(w, http.StatusOK, map[string]any{"channel": toNotificationChannelJSON(ch), "signingSecret": secret})
}

// GET /v1/notifications/deliveries?channelId=&limit= — admin. Newest first.
func (s *Server) handleV1ListNotificationDeliveries(w http.ResponseWriter, r *http.Request) {
	_, ctx, account, ok := s.notificationAdmin(w, r)
	if !ok {
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxNotificationLog {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("limit must be between 1 and %d", maxNotificationLog))
			return
		}
		limit = n
	}
	channelID := strings.TrimSpace(r.URL.Query().Get("channelId"))
	if channelID != "" {
		if _, err := s.store.GetNotificationChannel(ctx, account, channelID); err != nil {
			if errors.Is(err, store.ErrNotificationChannelNotFound) {
				writeNativeError(w, http.StatusNotFound, "not_found", "notification channel not found")
				return
			}
			log.Printf("notifications: channel read failed: %v", err)
			writeNativeError(w, http.StatusInternalServerError, "notifications_failed", "the delivery log could not be read")
			return
		}
	}
	list, err := s.store.ListNotificationDeliveries(ctx, account, channelID, limit)
	if err != nil {
		log.Printf("notifications: delivery log read failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "notifications_failed", "the delivery log could not be read")
		return
	}
	out := make([]notificationDeliveryJSON, 0, len(list))
	for _, d := range list {
		out = append(out, toNotificationDeliveryJSON(d))
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"deliveries": out})
}

// POST /v1/notifications/deliveries/retry — admin. Requeues a dead-lettered
// delivery with its attempts reset.
func (s *Server) handleV1RetryNotificationDelivery(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.RetryNotificationDelivery"
	_, ctx, account, ok := s.notificationAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		ID int64 `json:"id"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		s.notificationFail(w, r, ctx, action, "", badNotification("invalid JSON body"))
		return
	}
	resource := strconv.FormatInt(req.ID, 10)
	if err := s.store.RequeueNotificationDelivery(ctx, account, req.ID); err != nil {
		s.notificationFail(w, r, ctx, action, resource, err)
		return
	}
	s.notificationOK(r, ctx, action, resource)
	s.kickNotifications()
	writeNativeJSON(w, http.StatusOK, map[string]bool{"requeued": true})
}
