package sdkgotest_test

import (
	"context"
	"testing"

	"github.com/worlddrknss/citadel/internal/servertest"
	citadel "github.com/worlddrknss/citadel/sdk/citadel/v2"
)

func TestAuditRetention(t *testing.T) {
	env := servertest.New(t)
	ctx := context.Background()
	admin := newClient(t, env, env.Admin)
	viewer := newClient(t, env, env.Viewer)

	got, err := viewer.GetAuditRetention(ctx)
	if err != nil || got.RetentionDays != 0 || got.Source != "deployment" || got.AccountDays != nil || got.MinDays != 7 {
		t.Fatalf("default = %+v, %v", got, err)
	}
	days := 90
	if _, err := viewer.SetAuditRetention(ctx, &days); citadel.ErrorCode(err) != citadel.CodeForbidden {
		t.Fatalf("viewer set = %v", err)
	}
	bad := 2
	if _, err := admin.SetAuditRetention(ctx, &bad); citadel.ErrorCode(err) != citadel.CodeInvalidRequest {
		t.Fatalf("2 days = %v", err)
	}
	got, err = admin.SetAuditRetention(ctx, &days)
	if err != nil || got.RetentionDays != 90 || got.Source != "account" || got.AccountDays == nil || *got.AccountDays != 90 {
		t.Fatalf("set = %+v, %v", got, err)
	}
	p, err := admin.PreviewAuditRetention(ctx, 30)
	if err != nil || p.RetentionDays != 30 || p.Cutoff == "" || p.PrunableEvents != 0 || p.Events == 0 {
		t.Fatalf("preview = %+v, %v", p, err)
	}
	got, err = admin.SetAuditRetention(ctx, nil)
	if err != nil || got.Source != "deployment" || got.AccountDays != nil {
		t.Fatalf("reset = %+v, %v", got, err)
	}
	v, err := viewer.VerifyAuditChain(ctx)
	if err != nil || v.Status != "verified" || v.Anchor != nil {
		t.Fatalf("verify = %+v, %v", v, err)
	}
}
