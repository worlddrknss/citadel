package postgres

import (
	"context"
	"testing"

	"github.com/worlddrknss/citadel/internal/store/storetest"
)

func TestNotificationStore(t *testing.T) {
	st, err := Open(context.Background(), testDB(t), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	storetest.NotificationStore(t, st)
}
