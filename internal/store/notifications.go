package store

import (
	"context"
	"errors"
	"time"
)

// Notification channels: account-scoped destinations (a signed webhook, a
// Slack incoming webhook, or email) that subscribe to typed events, and a
// durable outbox of deliveries to them. The outbox doubles as each
// channel's delivery log.

// Notification channel types.
const (
	NotificationWebhook = "webhook"
	NotificationSlack   = "slack"
	NotificationEmail   = "email"
)

// Notification delivery statuses.
const (
	// NotificationPending: waiting for its first or next attempt (Attempts
	// says which).
	NotificationPending = "pending"
	// NotificationDelivered: the destination accepted it.
	NotificationDelivered = "delivered"
	// NotificationDead: retries are exhausted (dead-lettered). A dead
	// delivery can be requeued.
	NotificationDead = "dead"
)

var (
	ErrNotificationChannelNotFound  = errors.New("notification channel not found")
	ErrNotificationChannelExists    = errors.New("a notification channel with this name already exists")
	ErrNotificationDeliveryNotFound = errors.New("notification delivery not found")
)

// NotificationChannel is one destination. Secrets are sealed by the server
// before they reach the store.
type NotificationChannel struct {
	ID        string
	AccountID string
	Name      string
	Type      string
	Enabled   bool
	// Events are the event types the channel receives.
	Events []string
	// URL is the webhook URL (webhook channels; "" otherwise).
	URL string
	// URLSealed is the Slack incoming webhook URL, which is itself a
	// credential (slack channels).
	URLSealed []byte
	// URLHint is a display form of the Slack URL without its secret part.
	URLHint string
	// Recipients are the email addresses (email channels).
	Recipients []string
	// SecretSealed is the webhook's HMAC signing secret.
	SecretSealed []byte
	CreatedAt    time.Time
	CreatedBy    string
	UpdatedAt    time.Time
	UpdatedBy    string
}

// NotificationEnqueue is one event to fan out.
type NotificationEnqueue struct {
	AccountID string
	EventID   string
	EventType string
	// Payload is the JSON event body stored with each delivery.
	Payload string
	// ChannelID targets one channel regardless of its subscriptions or
	// whether it is enabled (test sends). Empty fans out to every enabled
	// channel subscribed to EventType.
	ChannelID string
}

// NotificationDelivery is one event queued for (or delivered to) one
// channel.
type NotificationDelivery struct {
	ID         int64
	AccountID  string
	ChannelID  string
	EventID    string
	EventType  string
	Payload    string
	Status     string
	Attempts   int
	LastError  string
	StatusCode int
	CreatedAt  time.Time
	// NextAttemptAt is when a pending delivery is tried next.
	NextAttemptAt *time.Time
	// LastAttemptAt is when it was last tried (nil before the first try).
	LastAttemptAt *time.Time
	DeliveredAt   *time.Time
	// LeaseToken identifies a claim; Complete and Retry need it.
	LeaseToken string
}

// NotificationStore persists channels and the delivery outbox. Channel and
// log reads and writes take the account explicitly; the claim and purge
// calls used by the background worker span every account.
type NotificationStore interface {
	ListNotificationChannels(ctx context.Context, accountID string) ([]NotificationChannel, error)
	GetNotificationChannel(ctx context.Context, accountID, id string) (NotificationChannel, error)
	// CreateNotificationChannel stores a new channel
	// (ErrNotificationChannelExists when the name is taken).
	CreateNotificationChannel(ctx context.Context, ch NotificationChannel) error
	// UpdateNotificationChannel replaces a channel's settings and secrets.
	UpdateNotificationChannel(ctx context.Context, ch NotificationChannel) error
	// DeleteNotificationChannel removes a channel and its deliveries.
	DeleteNotificationChannel(ctx context.Context, accountID, id string) error

	// EnqueueNotification queues n for its channels and returns how many
	// deliveries it created.
	EnqueueNotification(ctx context.Context, n NotificationEnqueue) (int, error)
	// ClaimNotificationDeliveries leases up to limit due pending deliveries
	// for lease, so that concurrent workers (on any replica) never take the
	// same one. Each claimed delivery carries a fresh LeaseToken.
	ClaimNotificationDeliveries(ctx context.Context, limit int, lease time.Duration) ([]NotificationDelivery, error)
	// CompleteNotificationDelivery marks a claimed delivery delivered. A
	// stale lease token is ignored.
	CompleteNotificationDelivery(ctx context.Context, id int64, leaseToken string, statusCode int) error
	// RetryNotificationDelivery records a failed attempt: pending again at
	// next, or dead when dead is set. A stale lease token is ignored.
	RetryNotificationDelivery(ctx context.Context, id int64, leaseToken string, next time.Time, lastErr string, statusCode int, dead bool) error
	// ListNotificationDeliveries returns the newest deliveries first, for
	// one channel or (channelID "") the whole account.
	ListNotificationDeliveries(ctx context.Context, accountID, channelID string, limit int) ([]NotificationDelivery, error)
	// RequeueNotificationDelivery makes a dead delivery pending again with
	// its attempts reset.
	RequeueNotificationDelivery(ctx context.Context, accountID string, id int64) error
	// PurgeNotificationDeliveries deletes delivered and dead deliveries
	// created before before.
	PurgeNotificationDeliveries(ctx context.Context, before time.Time) (int64, error)
}

// MaxNotificationError is the longest LastError kept.
const MaxNotificationError = 500

// TruncateNotificationError shortens an error for storage.
func TruncateNotificationError(s string) string {
	if len(s) > MaxNotificationError {
		return s[:MaxNotificationError]
	}
	return s
}
