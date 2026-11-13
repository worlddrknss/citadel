package postgres

import (
	"context"
	"testing"

	"github.com/worlddrknss/citadel/internal/store/storetest"
)

func TestWriteAheadAudit(t *testing.T) {
	db := testDB(t)
	st, err := Open(context.Background(), db, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	_, acct := st.DeploymentIdentity()
	storetest.WriteAheadAudit(t, st, acct)
}
