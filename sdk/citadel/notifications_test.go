package citadel_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/servertest"
	"github.com/worlddrknss/citadel/sdk/citadel"
)

func TestNotificationChannels(t *testing.T) {
	env := servertest.New(t)
	ctx := context.Background()
	admin := newClient(t, env, env.Admin)

	if _, err := newClient(t, env, env.Editor).ListNotificationChannels(ctx); citadel.ErrorCode(err) != citadel.CodeForbidden {
		t.Fatalf("editor list = %v", err)
	}
	saved, err := admin.CreateNotificationChannel(ctx, citadel.CreateNotificationChannelInput{
		Name: "ops", Type: citadel.NotificationWebhook, URL: "https://hooks.example.com/citadel",
		Events: []string{citadel.EventAgentSuspended, citadel.EventSecurityKillSwitch},
	})
	if err != nil {
		t.Fatal(err)
	}
	if saved.SigningSecret == "" || !saved.Channel.HasSigningSecret || !saved.Channel.Enabled || len(saved.Channel.Events) != 2 {
		t.Fatalf("created = %+v", saved)
	}
	id := saved.Channel.ID

	list, err := admin.ListNotificationChannels(ctx)
	if err != nil || len(list.Channels) != 1 || len(list.Events) == 0 || list.EmailAvailable {
		t.Fatalf("list = %+v, %v", list, err)
	}

	off := false
	name := "ops-hook"
	ch, err := admin.UpdateNotificationChannel(ctx, citadel.UpdateNotificationChannelInput{ID: id, Name: &name, Enabled: &off})
	if err != nil || ch.Name != "ops-hook" || ch.Enabled || len(ch.Events) != 2 {
		t.Fatalf("update = %+v, %v", ch, err)
	}
	ch, err = admin.UpdateNotificationChannel(ctx, citadel.UpdateNotificationChannelInput{ID: id, Events: []string{}})
	if err != nil || len(ch.Events) != 0 {
		t.Fatalf("unsubscribe = %+v, %v", ch, err)
	}

	secret, err := admin.RotateNotificationSigningSecret(ctx, id)
	if err != nil || secret == "" || secret == saved.SigningSecret {
		t.Fatalf("rotate = %q, %v", secret, err)
	}
	eventID, err := admin.TestNotificationChannel(ctx, id)
	if err != nil || eventID == "" {
		t.Fatalf("test = %q, %v", eventID, err)
	}
	log, err := admin.ListNotificationDeliveries(ctx, id, 10)
	if err != nil || len(log) != 1 || log[0].EventID != eventID || log[0].EventType != citadel.EventTest {
		t.Fatalf("log = %+v, %v", log, err)
	}
	if err := admin.RetryNotificationDelivery(ctx, log[0].ID); !citadel.IsNotFound(err) {
		t.Fatalf("retry pending = %v", err)
	}
	if err := admin.DeleteNotificationChannel(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := admin.DeleteNotificationChannel(ctx, id); !citadel.IsNotFound(err) {
		t.Fatalf("delete again = %v", err)
	}
}

func TestVerifyNotificationSignature(t *testing.T) {
	secret := "whsec_0123456789abcdef0123456789abcdef"
	body := []byte(`{"id":"evt_1","type":"test"}`)
	sign := func(ts int64, b []byte) string {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(strconv.FormatInt(ts, 10) + "."))
		mac.Write(b)
		return "t=" + strconv.FormatInt(ts, 10) + ",v1=" + hex.EncodeToString(mac.Sum(nil))
	}
	now := time.Now().Unix()
	if err := citadel.VerifyNotificationSignature(secret, sign(now, body), body, 0); err != nil {
		t.Fatal(err)
	}
	for name, hdr := range map[string]string{
		"tampered body": sign(now, []byte(`{"id":"evt_2"}`)),
		"too old":       sign(now-3600, body),
		"no timestamp":  "v1=00",
		"garbage":       "nonsense",
	} {
		if err := citadel.VerifyNotificationSignature(secret, hdr, body, 0); !errors.Is(err, citadel.ErrInvalidSignature) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := citadel.VerifyNotificationSignature("whsec_another_secret_0123456789abcdef", sign(now, body), body, 0); !errors.Is(err, citadel.ErrInvalidSignature) {
		t.Fatalf("wrong secret = %v", err)
	}
}
