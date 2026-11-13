package citadel

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ---- Notifications ----------------------------------------------------------

// Notification channel types.
const (
	NotificationWebhook = "webhook"
	NotificationSlack   = "slack"
	NotificationEmail   = "email"
)

// Notification event types.
const (
	EventAgentApprovalRequested = "agent.approval_requested"
	EventAgentSuspended         = "agent.suspended"
	EventAgentAnomaly           = "agent.anomaly"
	EventSecurityKillSwitch     = "security.kill_switch"
	EventTest                   = "test"
)

// NotificationChannel is a destination for notifications. Secrets are never
// returned: HasSigningSecret says whether a webhook has one, and URLHint
// shows a Slack URL without its secret part.
type NotificationChannel struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Type             string    `json:"type"`
	Enabled          bool      `json:"enabled"`
	Events           []string  `json:"events"`
	URL              string    `json:"url,omitempty"`
	URLHint          string    `json:"urlHint,omitempty"`
	Recipients       []string  `json:"recipients,omitempty"`
	HasSigningSecret bool      `json:"hasSigningSecret"`
	CreatedAt        time.Time `json:"createdAt"`
	CreatedBy        string    `json:"createdBy"`
	UpdatedAt        time.Time `json:"updatedAt"`
	UpdatedBy        string    `json:"updatedBy"`
}

// NotificationEventType describes an event channels can subscribe to.
type NotificationEventType struct {
	Type        string `json:"type"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// NotificationChannels is the result of ListNotificationChannels.
type NotificationChannels struct {
	Channels []NotificationChannel  `json:"channels"`
	Events   []NotificationEventType `json:"events"`
	// EmailAvailable says whether the server has SMTP settings.
	EmailAvailable bool `json:"emailAvailable"`
}

// ListNotificationChannels returns the account's channels and the event
// catalog. Requires the admin role.
func (c *Client) ListNotificationChannels(ctx context.Context) (*NotificationChannels, error) {
	var out NotificationChannels
	if err := c.do(ctx, http.MethodGet, "/v1/notifications/channels", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateNotificationChannelInput is a channel to create.
type CreateNotificationChannelInput struct {
	Name string `json:"name"`
	// Type is NotificationWebhook, NotificationSlack or NotificationEmail.
	Type string `json:"type"`
	// Enabled defaults to true.
	Enabled *bool    `json:"enabled,omitempty"`
	Events  []string `json:"events"`
	// URL is the webhook URL, or the Slack incoming webhook URL.
	URL string `json:"url,omitempty"`
	// Recipients are the email addresses (email channels).
	Recipients []string `json:"recipients,omitempty"`
}

// SavedNotificationChannel is a channel returned by a change. SigningSecret
// is set, once, when a webhook channel is created or its secret rotated.
type SavedNotificationChannel struct {
	Channel       NotificationChannel `json:"channel"`
	SigningSecret string              `json:"signingSecret,omitempty"`
}

// CreateNotificationChannel creates a channel. Requires the admin role.
func (c *Client) CreateNotificationChannel(ctx context.Context, in CreateNotificationChannelInput) (*SavedNotificationChannel, error) {
	if in.Events == nil {
		in.Events = []string{}
	}
	var out SavedNotificationChannel
	if err := c.do(ctx, http.MethodPost, "/v1/notifications/channels", nil, in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateNotificationChannelInput changes a channel; nil members are kept
// (an empty, non-nil Events unsubscribes from everything).
type UpdateNotificationChannelInput struct {
	ID         string   `json:"id"`
	Name       *string  `json:"name,omitempty"`
	Enabled    *bool    `json:"enabled,omitempty"`
	Events     []string `json:"events"`
	URL        *string  `json:"url,omitempty"`
	Recipients []string `json:"recipients"`
}

// UpdateNotificationChannel changes a channel. Requires the admin role.
func (c *Client) UpdateNotificationChannel(ctx context.Context, in UpdateNotificationChannelInput) (*NotificationChannel, error) {
	var out SavedNotificationChannel
	if err := c.do(ctx, http.MethodPost, "/v1/notifications/channels/update", nil, in, &out); err != nil {
		return nil, err
	}
	return &out.Channel, nil
}

// DeleteNotificationChannel deletes a channel and its delivery log.
func (c *Client) DeleteNotificationChannel(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/notifications/channels", url.Values{"id": {id}}, nil, nil)
}

// TestNotificationChannel queues a test event for the channel and returns
// its event ID. The outcome appears in ListNotificationDeliveries.
func (c *Client) TestNotificationChannel(ctx context.Context, id string) (string, error) {
	var out struct {
		EventID string `json:"eventId"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/notifications/channels/test", nil, map[string]string{"id": id}, &out); err != nil {
		return "", err
	}
	return out.EventID, nil
}

// RotateNotificationSigningSecret replaces a webhook channel's signing
// secret and returns the new one.
func (c *Client) RotateNotificationSigningSecret(ctx context.Context, id string) (string, error) {
	var out SavedNotificationChannel
	if err := c.do(ctx, http.MethodPost, "/v1/notifications/channels/signing-secret", nil, map[string]string{"id": id}, &out); err != nil {
		return "", err
	}
	return out.SigningSecret, nil
}

// Notification delivery statuses.
const (
	DeliveryPending   = "pending"
	DeliveryDelivered = "delivered"
	DeliveryDead      = "dead"
)

// NotificationDelivery is one entry in a channel's delivery log.
type NotificationDelivery struct {
	ID            int64           `json:"id"`
	ChannelID     string          `json:"channelId"`
	EventID       string          `json:"eventId"`
	EventType     string          `json:"eventType"`
	Status        string          `json:"status"`
	Attempts      int             `json:"attempts"`
	LastError     string          `json:"lastError,omitempty"`
	StatusCode    int             `json:"statusCode,omitempty"`
	CreatedAt     time.Time       `json:"createdAt"`
	NextAttemptAt *time.Time      `json:"nextAttemptAt,omitempty"`
	LastAttemptAt *time.Time      `json:"lastAttemptAt,omitempty"`
	DeliveredAt   *time.Time      `json:"deliveredAt,omitempty"`
	Data          json.RawMessage `json:"data"`
}

// ListNotificationDeliveries returns the newest deliveries first, for one
// channel or (channelID "") the whole account. limit 0 means the server's
// default (50); the maximum is 200.
func (c *Client) ListNotificationDeliveries(ctx context.Context, channelID string, limit int) ([]NotificationDelivery, error) {
	q := url.Values{}
	if channelID != "" {
		q.Set("channelId", channelID)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var out struct {
		Deliveries []NotificationDelivery `json:"deliveries"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/notifications/deliveries", q, nil, &out); err != nil {
		return nil, err
	}
	return out.Deliveries, nil
}

// RetryNotificationDelivery requeues a dead-lettered delivery.
func (c *Client) RetryNotificationDelivery(ctx context.Context, id int64) error {
	return c.do(ctx, http.MethodPost, "/v1/notifications/deliveries/retry", nil, map[string]int64{"id": id}, nil)
}

// ---- receiving webhooks -----------------------------------------------------

// NotificationEvent is the JSON body of a webhook notification.
type NotificationEvent struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	AccountID string          `json:"accountId"`
	CreatedAt time.Time       `json:"createdAt"`
	Data      json.RawMessage `json:"data"`
}

// ErrInvalidSignature is returned by VerifyNotificationSignature.
var ErrInvalidSignature = errors.New("citadel: invalid notification signature")

// DefaultSignatureTolerance is how far a signature's timestamp may be from
// now before VerifyNotificationSignature rejects it as a replay.
const DefaultSignatureTolerance = 5 * time.Minute

// VerifyNotificationSignature checks a webhook's X-Citadel-Signature header
// ("t=<unix>,v1=<hex>") against the raw request body and the channel's
// signing secret, and rejects timestamps more than tolerance from now (0
// means DefaultSignatureTolerance). Pass the body exactly as received.
func VerifyNotificationSignature(secret, header string, body []byte, tolerance time.Duration) error {
	if tolerance <= 0 {
		tolerance = DefaultSignatureTolerance
	}
	var ts string
	var sigs []string
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "t":
			ts = v
		case "v1":
			sigs = append(sigs, v)
		}
	}
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || len(sigs) == 0 {
		return ErrInvalidSignature
	}
	if d := time.Since(time.Unix(n, 0)); d > tolerance || d < -tolerance {
		return ErrInvalidSignature
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	for _, s := range sigs {
		if hmac.Equal([]byte(s), []byte(want)) {
			return nil
		}
	}
	return ErrInvalidSignature
}
