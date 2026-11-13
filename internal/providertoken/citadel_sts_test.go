package providertoken_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/providertoken"
	"github.com/worlddrknss/citadel/internal/servertest"
	"github.com/worlddrknss/citadel/internal/store"
)

// TestAWSSTSAgainstCitadel assumes a role on Citadel's own STS endpoint (the
// real server over the in-memory store) and then signs a brokered request
// with the temporary credentials.
func TestAWSSTSAgainstCitadel(t *testing.T) {
	env := servertest.New(t)
	ctx := context.Background()
	roleARN := "arn:aws:iam::" + env.AccountID + ":role/agent-broker"
	if err := env.Store.CreateIAMRole(ctx, store.IAMRole{
		RoleARN: roleARN, AccountID: env.AccountID, RoleName: "agent-broker",
		Trust:          store.TrustPolicy{Type: "account", Principals: []string{env.AccountID}},
		MaxSessionSecs: 3600,
	}); err != nil {
		t.Fatal(err)
	}
	a, err := providertoken.NewAWSSTS(providertoken.AWSSTSConfig{
		Endpoint:          env.URL + "/",
		Region:            "local",
		Source:            providertoken.AWSCredentials{AccessKeyID: env.Editor.ID, SecretAccessKey: env.Editor.Secret},
		RoleARN:           roleARN,
		AllowInsecureHTTP: true,
	}, env.HTTP.Client())
	if err != nil {
		t.Fatal(err)
	}
	r, err := a.AssumeRole(ctx, providertoken.Params{SessionName: "agent-7", Duration: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(r.Credentials.AccessKeyID, "ASIA") || !strings.Contains(r.AssumedARN, "assumed-role/agent-broker/agent-7") ||
		r.Credentials.Expiration.Before(time.Now()) || r.Credentials.SessionToken == "" {
		t.Fatalf("AssumeRole = %s %s exp=%v", r.Credentials, r.AssumedARN, r.Credentials.Expiration)
	}

	// A brokered call signed server-side with the temporary credentials.
	body := "Action=GetCallerIdentity&Version=2011-06-15"
	req, _ := http.NewRequest(http.MethodPost, env.URL+"/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	if err := providertoken.SignAWSRequest(req, r.Credentials, "local", "sts", time.Now()); err != nil {
		t.Fatal(err)
	}
	resp, err := env.HTTP.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(out), ":assumed-role/") {
		t.Fatalf("GetCallerIdentity with temporary credentials: HTTP %d %s", resp.StatusCode, out)
	}
}
