package memory

import (
	"context"
	"slices"
	"sort"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// memNotifications holds notification channels and the delivery outbox. All
// access is under Store.mu, which makes a claim atomic: the in-memory
// equivalent of SELECT ... FOR UPDATE SKIP LOCKED.
type memNotifications struct {
	channels   map[string]store.NotificationChannel // id -> channel
	deliveries []*store.NotificationDelivery
	seq        int64
}

func (s *Store) notifState() *memNotifications {
	if s.notif == nil {
		s.notif = &memNotifications{channels: map[string]store.NotificationChannel{}}
	}
	return s.notif
}

func cloneChannel(ch store.NotificationChannel) store.NotificationChannel {
	ch.Events = slices.Clone(ch.Events)
	ch.Recipients = slices.Clone(ch.Recipients)
	ch.URLSealed = slices.Clone(ch.URLSealed)
	ch.SecretSealed = slices.Clone(ch.SecretSealed)
	return ch
}

func (s *Store) ListNotificationChannels(_ context.Context, accountID string) ([]store.NotificationChannel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.NotificationChannel
	for _, ch := range s.notifState().channels {
		if ch.AccountID == accountID {
			out = append(out, cloneChannel(ch))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) GetNotificationChannel(_ context.Context, accountID, id string) (store.NotificationChannel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.notifState().channels[id]
	if !ok || ch.AccountID != accountID {
		return store.NotificationChannel{}, store.ErrNotificationChannelNotFound
	}
	return cloneChannel(ch), nil
}

func (n *memNotifications) nameTaken(accountID, name, exceptID string) bool {
	for _, ch := range n.channels {
		if ch.AccountID == accountID && ch.Name == name && ch.ID != exceptID {
			return true
		}
	}
	return false
}

func (s *Store) CreateNotificationChannel(_ context.Context, ch store.NotificationChannel) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.notifState()
	if _, dup := n.channels[ch.ID]; dup || n.nameTaken(ch.AccountID, ch.Name, "") {
		return store.ErrNotificationChannelExists
	}
	now := time.Now().UTC()
	ch.CreatedAt, ch.UpdatedAt, ch.UpdatedBy = now, now, ch.CreatedBy
	n.channels[ch.ID] = cloneChannel(ch)
	return nil
}

func (s *Store) UpdateNotificationChannel(_ context.Context, ch store.NotificationChannel) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.notifState()
	cur, ok := n.channels[ch.ID]
	if !ok || cur.AccountID != ch.AccountID {
		return store.ErrNotificationChannelNotFound
	}
	if n.nameTaken(ch.AccountID, ch.Name, ch.ID) {
		return store.ErrNotificationChannelExists
	}
	ch.Type, ch.CreatedAt, ch.CreatedBy = cur.Type, cur.CreatedAt, cur.CreatedBy
	ch.UpdatedAt = time.Now().UTC()
	n.channels[ch.ID] = cloneChannel(ch)
	return nil
}

func (s *Store) DeleteNotificationChannel(_ context.Context, accountID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.notifState()
	cur, ok := n.channels[id]
	if !ok || cur.AccountID != accountID {
		return store.ErrNotificationChannelNotFound
	}
	delete(n.channels, id)
	n.deliveries = slices.DeleteFunc(n.deliveries, func(d *store.NotificationDelivery) bool { return d.ChannelID == id })
	return nil
}

func (s *Store) EnqueueNotification(_ context.Context, e store.NotificationEnqueue) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.notifState()
	var targets []store.NotificationChannel
	if e.ChannelID != "" {
		if ch, ok := n.channels[e.ChannelID]; ok && ch.AccountID == e.AccountID {
			targets = append(targets, ch)
		}
	} else {
		for _, ch := range n.channels {
			if ch.AccountID == e.AccountID && ch.Enabled && slices.Contains(ch.Events, e.EventType) {
				targets = append(targets, ch)
			}
		}
		sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })
	}
	now := time.Now().UTC()
	for _, ch := range targets {
		n.seq++
		next := now
		n.deliveries = append(n.deliveries, &store.NotificationDelivery{
			ID: n.seq, AccountID: e.AccountID, ChannelID: ch.ID, EventID: e.EventID, EventType: e.EventType,
			Payload: e.Payload, Status: store.NotificationPending, CreatedAt: now, NextAttemptAt: &next,
		})
	}
	return len(targets), nil
}

func copyDelivery(d *store.NotificationDelivery) store.NotificationDelivery {
	out := *d
	for _, p := range []**time.Time{&out.NextAttemptAt, &out.LastAttemptAt, &out.DeliveredAt} {
		if *p != nil {
			t := **p
			*p = &t
		}
	}
	return out
}

func (s *Store) ClaimNotificationDeliveries(_ context.Context, limit int, lease time.Duration) ([]store.NotificationDelivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	var due []*store.NotificationDelivery
	for _, d := range s.notifState().deliveries {
		if d.Status == store.NotificationPending && d.NextAttemptAt != nil && !d.NextAttemptAt.After(now) {
			due = append(due, d)
		}
	}
	sort.SliceStable(due, func(i, j int) bool {
		if !due[i].NextAttemptAt.Equal(*due[j].NextAttemptAt) {
			return due[i].NextAttemptAt.Before(*due[j].NextAttemptAt)
		}
		return due[i].ID < due[j].ID
	})
	if len(due) > limit {
		due = due[:limit]
	}
	out := make([]store.NotificationDelivery, 0, len(due))
	until := now.Add(lease)
	for _, d := range due {
		d.LeaseToken = cryptoutil.RandomHex(16)
		t := until
		d.NextAttemptAt = &t
		out = append(out, copyDelivery(d))
	}
	return out, nil
}

func (n *memNotifications) leased(id int64, token string) *store.NotificationDelivery {
	for _, d := range n.deliveries {
		if d.ID == id && d.Status == store.NotificationPending && d.LeaseToken != "" && d.LeaseToken == token {
			return d
		}
	}
	return nil
}

func (s *Store) CompleteNotificationDelivery(_ context.Context, id int64, leaseToken string, statusCode int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.notifState().leased(id, leaseToken)
	if d == nil {
		return nil
	}
	now := time.Now().UTC()
	d.Status, d.StatusCode, d.LastError, d.LeaseToken = store.NotificationDelivered, statusCode, "", ""
	d.Attempts++
	d.LastAttemptAt, d.DeliveredAt, d.NextAttemptAt = &now, &now, nil
	return nil
}

func (s *Store) RetryNotificationDelivery(_ context.Context, id int64, leaseToken string, next time.Time, lastErr string, statusCode int, dead bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.notifState().leased(id, leaseToken)
	if d == nil {
		return nil
	}
	now := time.Now().UTC()
	d.Attempts++
	d.LastAttemptAt, d.LastError, d.StatusCode, d.LeaseToken = &now, store.TruncateNotificationError(lastErr), statusCode, ""
	if dead {
		d.Status, d.NextAttemptAt = store.NotificationDead, nil
	} else {
		t := next.UTC()
		d.NextAttemptAt = &t
	}
	return nil
}

func (s *Store) ListNotificationDeliveries(_ context.Context, accountID, channelID string, limit int) ([]store.NotificationDelivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 {
		limit = 50
	}
	var out []store.NotificationDelivery
	ds := s.notifState().deliveries
	for i := len(ds) - 1; i >= 0 && len(out) < limit; i-- {
		d := ds[i]
		if d.AccountID == accountID && (channelID == "" || d.ChannelID == channelID) {
			c := copyDelivery(d)
			c.LeaseToken = ""
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *Store) RequeueNotificationDelivery(_ context.Context, accountID string, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.notifState().deliveries {
		if d.ID == id && d.AccountID == accountID && d.Status == store.NotificationDead {
			now := time.Now().UTC()
			d.Status, d.Attempts, d.NextAttemptAt, d.LeaseToken = store.NotificationPending, 0, &now, ""
			return nil
		}
	}
	return store.ErrNotificationDeliveryNotFound
}

func (s *Store) PurgeNotificationDeliveries(_ context.Context, before time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.notifState()
	var purged int64
	n.deliveries = slices.DeleteFunc(n.deliveries, func(d *store.NotificationDelivery) bool {
		if d.Status != store.NotificationPending && d.CreatedAt.Before(before) {
			purged++
			return true
		}
		return false
	})
	return purged, nil
}
