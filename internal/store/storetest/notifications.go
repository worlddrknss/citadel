package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// NotificationStore checks store.NotificationStore: channel CRUD and name
// uniqueness, tenancy, fan-out by subscription, the claim lease (no
// delivery is claimed twice, even concurrently), retries, dead-lettering,
// requeue, the delivery log and purging.
func NotificationStore(t *testing.T, st store.NotificationStore) {
	ctx := context.Background()

	hook := store.NotificationChannel{
		ID: "nch_a1", AccountID: AccountA, Name: "ops-hook", Type: store.NotificationWebhook, Enabled: true,
		Events: []string{"agent.suspended", "security.kill_switch"}, URL: "https://hooks.example.com/citadel",
		SecretSealed: []byte{1, 2, 3}, CreatedBy: "alice",
	}
	slack := store.NotificationChannel{
		ID: "nch_a2", AccountID: AccountA, Name: "ops-slack", Type: store.NotificationSlack, Enabled: true,
		Events: []string{"agent.suspended"}, URLSealed: []byte{9}, URLHint: "hooks.slack.com/services/T1/…", CreatedBy: "alice",
	}
	mail := store.NotificationChannel{
		ID: "nch_a3", AccountID: AccountA, Name: "ops-mail", Type: store.NotificationEmail, Enabled: false,
		Events: []string{"agent.suspended"}, Recipients: []string{"ops@example.com"}, CreatedBy: "alice",
	}
	other := store.NotificationChannel{
		ID: "nch_b1", AccountID: AccountB, Name: "ops-hook", Type: store.NotificationWebhook, Enabled: true,
		Events: []string{"agent.suspended"}, URL: "https://b.example.com/", CreatedBy: "bob",
	}
	for _, ch := range []store.NotificationChannel{hook, slack, mail, other} {
		if err := st.CreateNotificationChannel(ctx, ch); err != nil {
			t.Fatalf("create %s: %v", ch.ID, err)
		}
	}
	dup := hook
	dup.ID = "nch_a9"
	if err := st.CreateNotificationChannel(ctx, dup); !errors.Is(err, store.ErrNotificationChannelExists) {
		t.Fatalf("duplicate name = %v", err)
	}

	list, err := st.ListNotificationChannels(ctx, AccountA)
	if err != nil || len(list) != 3 || list[0].Name != "ops-hook" || list[2].Name != "ops-slack" {
		t.Fatalf("list A = %+v, %v", list, err)
	}
	got, err := st.GetNotificationChannel(ctx, AccountA, "nch_a1")
	if err != nil || got.URL != hook.URL || len(got.Events) != 2 || string(got.SecretSealed) != string(hook.SecretSealed) || got.CreatedBy != "alice" || got.CreatedAt.IsZero() {
		t.Fatalf("get = %+v, %v", got, err)
	}
	if _, err := st.GetNotificationChannel(ctx, AccountB, "nch_a1"); !errors.Is(err, store.ErrNotificationChannelNotFound) {
		t.Fatalf("cross-account get = %v", err)
	}

	// Update: rename, resubscribe, rotate the secret; another account can't.
	got.Name, got.Events, got.SecretSealed, got.UpdatedBy = "ops-webhook", []string{"agent.suspended", "test"}, []byte{4, 5}, "carol"
	if err := st.UpdateNotificationChannel(ctx, got); err != nil {
		t.Fatal(err)
	}
	upd, _ := st.GetNotificationChannel(ctx, AccountA, "nch_a1")
	if upd.Name != "ops-webhook" || len(upd.Events) != 2 || upd.Events[1] != "test" || string(upd.SecretSealed) != "\x04\x05" || upd.UpdatedBy != "carol" {
		t.Fatalf("updated = %+v", upd)
	}
	clash := upd
	clash.Name = "ops-slack"
	if err := st.UpdateNotificationChannel(ctx, clash); !errors.Is(err, store.ErrNotificationChannelExists) {
		t.Fatalf("rename onto taken name = %v", err)
	}
	foreign := upd
	foreign.AccountID = AccountB
	if err := st.UpdateNotificationChannel(ctx, foreign); !errors.Is(err, store.ErrNotificationChannelNotFound) {
		t.Fatalf("cross-account update = %v", err)
	}

	// Fan-out: enabled, subscribed channels in the account only.
	n, err := st.EnqueueNotification(ctx, store.NotificationEnqueue{AccountID: AccountA, EventID: "evt_1", EventType: "agent.suspended", Payload: `{"x":1}`})
	if err != nil || n != 2 {
		t.Fatalf("enqueue agent.suspended = %d, %v (want 2: webhook and slack; email is disabled)", n, err)
	}
	if n, _ := st.EnqueueNotification(ctx, store.NotificationEnqueue{AccountID: AccountA, EventID: "evt_2", EventType: "agent.anomaly", Payload: `{}`}); n != 0 {
		t.Fatalf("unsubscribed event fanned out to %d", n)
	}
	// A targeted send reaches a disabled channel, but not another account's.
	if n, _ := st.EnqueueNotification(ctx, store.NotificationEnqueue{AccountID: AccountA, EventID: "evt_3", EventType: "test", Payload: `{}`, ChannelID: "nch_a3"}); n != 1 {
		t.Fatalf("targeted send = %d", n)
	}
	if n, _ := st.EnqueueNotification(ctx, store.NotificationEnqueue{AccountID: AccountA, EventID: "evt_4", EventType: "test", Payload: `{}`, ChannelID: "nch_b1"}); n != 0 {
		t.Fatalf("cross-account targeted send = %d", n)
	}
	if n, _ := st.EnqueueNotification(ctx, store.NotificationEnqueue{AccountID: AccountB, EventID: "evt_5", EventType: "agent.suspended", Payload: `{}`}); n != 1 {
		t.Fatalf("account B fan-out = %d", n)
	}

	// Concurrent claims never hand out the same delivery.
	var mu sync.Mutex
	seen := map[int64]int{}
	var claimed []store.NotificationDelivery
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			items, err := st.ClaimNotificationDeliveries(ctx, 2, time.Minute)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, it := range items {
				seen[it.ID]++
				claimed = append(claimed, it)
			}
		}()
	}
	wg.Wait()
	if len(seen) != 4 {
		t.Fatalf("claimed %d distinct deliveries, want 4", len(seen))
	}
	for id, c := range seen {
		if c != 1 {
			t.Fatalf("delivery %d claimed %d times", id, c)
		}
	}
	if again, _ := st.ClaimNotificationDeliveries(ctx, 10, time.Minute); len(again) != 0 {
		t.Fatalf("leased deliveries claimed again: %d", len(again))
	}

	byChannel := map[string]store.NotificationDelivery{}
	for _, d := range claimed {
		if d.LeaseToken == "" || d.Payload == "" || d.EventID == "" {
			t.Fatalf("claimed delivery = %+v", d)
		}
		if d.AccountID == AccountA {
			byChannel[d.ChannelID+"/"+d.EventType] = d
		}
	}
	ok := byChannel["nch_a1/agent.suspended"]
	fail := byChannel["nch_a2/agent.suspended"]
	dead := byChannel["nch_a3/test"]

	// A stale token is ignored.
	if err := st.CompleteNotificationDelivery(ctx, ok.ID, "stale", 200); err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteNotificationDelivery(ctx, ok.ID, ok.LeaseToken, 204); err != nil {
		t.Fatal(err)
	}
	if err := st.RetryNotificationDelivery(ctx, fail.ID, fail.LeaseToken, time.Now().Add(-time.Second), "HTTP 500", 500, false); err != nil {
		t.Fatal(err)
	}
	if err := st.RetryNotificationDelivery(ctx, dead.ID, dead.LeaseToken, time.Now(), "smtp: refused", 0, true); err != nil {
		t.Fatal(err)
	}
	// Completing with the used token again changes nothing.
	if err := st.RetryNotificationDelivery(ctx, ok.ID, ok.LeaseToken, time.Now(), "late", 0, true); err != nil {
		t.Fatal(err)
	}

	log, err := st.ListNotificationDeliveries(ctx, AccountA, "", 10)
	if err != nil || len(log) != 3 {
		t.Fatalf("log A = %d, %v", len(log), err)
	}
	if log[0].ID < log[len(log)-1].ID {
		t.Fatal("log is not newest first")
	}
	status := map[int64]store.NotificationDelivery{}
	for _, d := range log {
		if d.LeaseToken != "" {
			t.Fatal("the log exposes lease tokens")
		}
		status[d.ID] = d
	}
	if d := status[ok.ID]; d.Status != store.NotificationDelivered || d.StatusCode != 204 || d.Attempts != 1 || d.DeliveredAt == nil || d.LastAttemptAt == nil {
		t.Fatalf("delivered = %+v", d)
	}
	if d := status[fail.ID]; d.Status != store.NotificationPending || d.Attempts != 1 || d.LastError != "HTTP 500" || d.StatusCode != 500 || d.NextAttemptAt == nil {
		t.Fatalf("retrying = %+v", d)
	}
	if d := status[dead.ID]; d.Status != store.NotificationDead || d.LastError != "smtp: refused" || d.NextAttemptAt != nil {
		t.Fatalf("dead = %+v", d)
	}
	if one, _ := st.ListNotificationDeliveries(ctx, AccountA, "nch_a2", 10); len(one) != 1 || one[0].ID != fail.ID {
		t.Fatalf("channel log = %+v", one)
	}
	if b, _ := st.ListNotificationDeliveries(ctx, AccountB, "", 10); len(b) != 1 {
		t.Fatalf("log B = %d", len(b))
	}

	// The retry is due again and can be claimed.
	again, err := st.ClaimNotificationDeliveries(ctx, 10, time.Minute)
	if err != nil || len(again) != 1 || again[0].ID != fail.ID || again[0].Attempts != 1 {
		t.Fatalf("reclaim = %+v, %v", again, err)
	}

	// Requeue: only dead deliveries, only in their account.
	if err := st.RequeueNotificationDelivery(ctx, AccountB, dead.ID); !errors.Is(err, store.ErrNotificationDeliveryNotFound) {
		t.Fatalf("cross-account requeue = %v", err)
	}
	if err := st.RequeueNotificationDelivery(ctx, AccountA, ok.ID); !errors.Is(err, store.ErrNotificationDeliveryNotFound) {
		t.Fatalf("requeue delivered = %v", err)
	}
	if err := st.RequeueNotificationDelivery(ctx, AccountA, dead.ID); err != nil {
		t.Fatal(err)
	}
	re, _ := st.ClaimNotificationDeliveries(ctx, 10, time.Minute)
	if len(re) != 1 || re[0].ID != dead.ID || re[0].Attempts != 0 {
		t.Fatalf("requeued claim = %+v", re)
	}

	// Purge removes finished deliveries older than the cutoff only.
	purged, err := st.PurgeNotificationDeliveries(ctx, time.Now().Add(time.Hour))
	if err != nil || purged != 1 {
		t.Fatalf("purge = %d, %v (want the delivered one)", purged, err)
	}

	// Deleting a channel deletes its deliveries; another account can't.
	if err := st.DeleteNotificationChannel(ctx, AccountB, "nch_a2"); !errors.Is(err, store.ErrNotificationChannelNotFound) {
		t.Fatalf("cross-account delete = %v", err)
	}
	if err := st.DeleteNotificationChannel(ctx, AccountA, "nch_a2"); err != nil {
		t.Fatal(err)
	}
	if left, _ := st.ListNotificationDeliveries(ctx, AccountA, "nch_a2", 10); len(left) != 0 {
		t.Fatalf("deliveries survived their channel: %d", len(left))
	}
	if err := st.DeleteNotificationChannel(ctx, AccountA, "nch_a2"); !errors.Is(err, store.ErrNotificationChannelNotFound) {
		t.Fatalf("second delete = %v", err)
	}
}
