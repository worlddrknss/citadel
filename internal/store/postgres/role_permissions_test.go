package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

func TestRolePermissionsAndSessionLookup(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	_, acct := st.DeploymentIdentity()
	roleARN := "arn:aws:iam::" + acct + ":role/app"
	policy := `{"Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`
	role := store.IAMRole{RoleARN: roleARN, AccountID: acct, RoleName: "app", Trust: store.TrustPolicy{Type: "account", Principals: []string{acct}}, PermissionsPolicy: policy}
	if err := st.CreateIAMRole(ctx, role); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetIAMRoleByARN(ctx, roleARN)
	if err != nil || got.PermissionsPolicy != policy {
		t.Fatalf("GetIAMRoleByARN = %q, %v", got.PermissionsPolicy, err)
	}
	role.PermissionsPolicy = ""
	if err := st.CreateIAMRole(ctx, role); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetIAMRole(ctx, acct, "app"); got.PermissionsPolicy != "" {
		t.Fatalf("policy after clearing = %q", got.PermissionsPolicy)
	}

	sess := store.STSSession{AccessKeyID: "ASIAROLEPERMTEST0001", AccountID: acct, RoleARN: roleARN, RoleSessionName: "eso", Subject: "sub", ExpiresAt: time.Now().Add(time.Hour)}
	if err := st.CreateSTSSession(ctx, sess, "secret-secret-secret", "token"); err != nil {
		t.Fatal(err)
	}
	gotSess, err := st.GetSTSSession(ctx, sess.AccessKeyID)
	if err != nil || gotSess.RoleARN != roleARN || gotSess.RoleSessionName != "eso" || gotSess.Subject != "sub" {
		t.Fatalf("GetSTSSession = %+v, %v", gotSess, err)
	}
	if _, err := st.GetSTSSession(ctx, "ASIANOPE"); !errors.Is(err, store.ErrSTSSessionNotFound) {
		t.Fatalf("missing session: %v", err)
	}
	expired := sess
	expired.AccessKeyID, expired.ExpiresAt = "ASIAROLEPERMTEST0002", time.Now().Add(-time.Minute)
	if err := st.CreateSTSSession(ctx, expired, "secret-secret-secret", "token"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSTSSession(ctx, expired.AccessKeyID); !errors.Is(err, store.ErrSTSSessionExpired) {
		t.Fatalf("expired session: %v", err)
	}
}
