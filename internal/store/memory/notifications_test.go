package memory

import (
	"testing"

	"github.com/worlddrknss/citadel/internal/store/storetest"
)

func TestNotificationStore(t *testing.T) {
	storetest.NotificationStore(t, &Store{})
}
