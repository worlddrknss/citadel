package server

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/worlddrknss/citadel/internal/store"
)

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, target string
		want            bool
	}{
		{"*", "anything", true},
		{"*", "*", true},
		{"arn:aws:secretsmanager:*:*:secret:shop/prod/*", "arn:aws:secretsmanager:us-east-1:123456789012:secret:shop/prod/DB", true},
		{"arn:aws:secretsmanager:*:*:secret:shop/prod/*", "arn:aws:secretsmanager:us-east-1:123456789012:secret:shop/staging/DB", false},
		{"arn:aws:secretsmanager:*:*:secret:shop/prod/*", "arn:aws:secretsmanager:us-east-1:123456789012:secret:shop/prodx", false},
		{"arn:aws:secretsmanager:*:*:secret:shop/prod/*", "*", false},
		{"secret:a?c", "secret:abc", true},
		{"secret:a?c", "secret:ac", false},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
		{"", "", true},
		{"", "x", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.target); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.target, got, c.want)
		}
	}
}

func TestParseRolePolicy(t *testing.T) {
	ok := []string{
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`,
		`{"Statement":{"Sid":"one","Effect":"Deny","Action":["kms:*"],"Resource":["*"]}}`,
		`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:secretsmanager:*:*:secret:a/*"}]}`,
	}
	for _, doc := range ok {
		if _, err := parseRolePolicy(doc); err != nil {
			t.Errorf("parseRolePolicy(%s) = %v", doc, err)
		}
	}
	bad := map[string]string{
		``:   "empty",
		`[]`: "not a valid policy document",
		`{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`: "Version",
		`{"Statement":[]}`: "no Statement",
		`{"Statement":[{"Effect":"allow","Action":"*","Resource":"*"}]}`:                 "Effect",
		`{"Statement":[{"Effect":"Allow","Resource":"*"}]}`:                              "Action is required",
		`{"Statement":[{"Effect":"Allow","Action":"*"}]}`:                                "Resource is required",
		`{"Statement":[{"Effect":"Allow","Action":"GetSecretValue","Resource":"*"}]}`:    "service:Action",
		`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Principal":"*"}]}`: "Principal",
		`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{}}]}`:  "Condition",
		`{"Statement":[{"Effect":"Allow","NotAction":"kms:*","Resource":"*"}]}`:          "NotAction",
		`{"Statement":[{"Effect":"Allow","Action":[],"Resource":"*"}]}`:                  "Action must be",
		`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}],"Id":"x"}`:        "unknown field",
		`{"Statement":[{"Effect":"Allow","Action":["kms:Encrypt",""],"Resource":"*"}]}`:  "empty value",
	}
	for doc, want := range bad {
		_, err := parseRolePolicy(doc)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("parseRolePolicy(%s) = %v, want an error mentioning %q", doc, err, want)
		}
	}
}

func TestRolePolicyEvaluation(t *testing.T) {
	p, err := parseRolePolicy(`{"Statement":[
		{"Effect":"Allow","Action":["secretsmanager:GetSecretValue","secretsmanager:ListSecrets"],"Resource":"arn:aws:secretsmanager:*:*:secret:shop/prod/*"},
		{"Effect":"Deny","Action":"secretsmanager:GetSecretValue","Resource":"arn:aws:secretsmanager:*:*:secret:shop/prod/ROOT*"},
		{"Effect":"Allow","Action":"kms:Decrypt","Resource":"*"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	secret := func(name string) string { return "arn:aws:secretsmanager:us-east-1:123456789012:secret:" + name }
	checks := []struct {
		action, resource string
		want             bool
	}{
		{"secretsmanager:GetSecretValue", secret("shop/prod/DB"), true},
		{"SecretsManager:getsecretvalue", secret("shop/prod/DB"), true}, // actions are case-insensitive
		{"secretsmanager:GetSecretValue", secret("shop/staging/DB"), false},
		{"secretsmanager:GetSecretValue", secret("shop/prod/ROOT_KEY"), false}, // explicit Deny wins
		{"secretsmanager:PutSecretValue", secret("shop/prod/DB"), false},       // not allowed
		{"kms:Decrypt", "*", true},
		{"kms:Encrypt", "*", false},
	}
	for _, c := range checks {
		if got := p.allows(c.action, c.resource); got != c.want {
			t.Errorf("allows(%s, %s) = %v, want %v", c.action, c.resource, got, c.want)
		}
	}
	gates := map[string]bool{
		"secretsmanager:GetSecretValue": true,  // resource-checked, some resource allowed
		"secretsmanager:ListSecrets":    true,  // filtered by the handler
		"secretsmanager:DeleteSecret":   false, // no statement allows it
		"kms:Decrypt":                   true,  // Resource "*"
		"kms:CreateKey":                 false,
		"":                              false, // unknown service
	}
	for action, want := range gates {
		if got := roleActionAllowed(p, action); got != want {
			t.Errorf("roleActionAllowed(%q) = %v, want %v", action, got, want)
		}
	}
	// A statement scoped to secrets never grants an action checked against "*".
	scoped, _ := parseRolePolicy(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:secretsmanager:*:*:secret:a/*"}]}`)
	if roleActionAllowed(scoped, "kms:CreateKey") || roleActionAllowed(scoped, "ssm:GetParameter") {
		t.Error("a secret-scoped Allow * granted a non-secret action")
	}
	if !roleActionAllowed(scoped, "secretsmanager:GetSecretValue") {
		t.Error("a secret-scoped Allow * did not pass the gate for GetSecretValue")
	}
	// A Deny on "*" refuses even resource-checked actions at the gate.
	denied, _ := parseRolePolicy(`{"Statement":[{"Effect":"Allow","Action":"secretsmanager:*","Resource":"*"},{"Effect":"Deny","Action":"secretsmanager:DeleteSecret","Resource":"*"}]}`)
	if roleActionAllowed(denied, "secretsmanager:DeleteSecret") || !roleActionAllowed(denied, "secretsmanager:GetSecretValue") {
		t.Error("Deny on * not applied at the gate")
	}
	var none *rolePolicy
	if none.allows("kms:Decrypt", "*") || roleActionAllowed(none, "kms:Decrypt") {
		t.Error("a nil policy (failed to parse) allowed a request")
	}
}

func TestIAMActionForTarget(t *testing.T) {
	for target, want := range map[string]string{
		"secretsmanager.GetSecretValue": "secretsmanager:GetSecretValue",
		"TrentService.Encrypt":          "kms:Encrypt",
		"AmazonSSM.GetParameter":        "ssm:GetParameter",
		"ACMPrivateCA.IssueCertificate": "acm-pca:IssueCertificate",
		"Unknown.Thing":                 "",
		"secretsmanager":                "",
	} {
		if got := iamActionForTarget(target); got != want {
			t.Errorf("iamActionForTarget(%q) = %q, want %q", target, got, want)
		}
	}
}

// TestSDKRolePermissions drives a restricted role session through the AWS
// SDK: it sees and reads only the secrets its policy allows, and everything
// else is refused.
func TestSDKRolePermissions(t *testing.T) {
	h := newSDKHarness(t)
	ctx := context.Background()
	for _, name := range []string{"app-a/prod/DB", "app-a/prod/API", "app-b/prod/DB", "app-a/staging/DB"} {
		must[*secretsmanager.CreateSecretOutput](t)(h.sm.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: aws.String(name), SecretString: aws.String("v-" + name)}))
	}
	mkRole := func(name, policy string) string {
		roleARN := "arn:aws:iam::" + harnessAccount + ":role/" + name
		if err := h.st.CreateIAMRole(ctx, store.IAMRole{RoleARN: roleARN, AccountID: harnessAccount, RoleName: name, MaxSessionSecs: 3600,
			Trust: store.TrustPolicy{Type: trustTypeAccount, Principals: []string{harnessAccount}}, PermissionsPolicy: policy}); err != nil {
			t.Fatal(err)
		}
		return roleARN
	}
	assume := func(roleARN string) (*kms.Client, *secretsmanager.Client, *ssm.Client, *sts.Client) {
		out := must[*sts.AssumeRoleOutput](t)(h.sts.AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: aws.String(roleARN), RoleSessionName: aws.String("eso")}))
		cr := out.Credentials
		return h.clients(credentials.NewStaticCredentialsProvider(aws.ToString(cr.AccessKeyId), aws.ToString(cr.SecretAccessKey), aws.ToString(cr.SessionToken)))
	}
	listNames := func(sm *secretsmanager.Client) []string {
		out := must[*secretsmanager.ListSecretsOutput](t)(sm.ListSecrets(ctx, &secretsmanager.ListSecretsInput{}))
		var names []string
		for _, e := range out.SecretList {
			names = append(names, aws.ToString(e.Name))
		}
		return names
	}

	const appAPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
		"Action":["secretsmanager:GetSecretValue","secretsmanager:DescribeSecret","secretsmanager:ListSecrets","secretsmanager:BatchGetSecretValue"],
		"Resource":"arn:aws:secretsmanager:*:*:secret:app-a/prod/*"}]}`
	roleA := mkRole("app-a-prod", appAPolicy)
	k, sm, ps, st := assume(roleA)

	id := must[*sts.GetCallerIdentityOutput](t)(st.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}))
	if !strings.HasSuffix(aws.ToString(id.Arn), ":assumed-role/app-a-prod/eso") {
		t.Fatalf("restricted session identity = %s", aws.ToString(id.Arn))
	}
	if got := strings.Join(listNames(sm), ","); got != "app-a/prod/API,app-a/prod/DB" {
		t.Fatalf("ListSecrets = %s, want only app-a/prod", got)
	}
	v := must[*secretsmanager.GetSecretValueOutput](t)(sm.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String("app-a/prod/DB")}))
	if aws.ToString(v.SecretString) != "v-app-a/prod/DB" {
		t.Fatalf("GetSecretValue = %q", aws.ToString(v.SecretString))
	}
	for _, other := range []string{"app-b/prod/DB", "app-a/staging/DB"} {
		_, err := sm.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(other)})
		wantCode(t, err, "AccessDeniedException")
		_, err = sm.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(other)})
		wantCode(t, err, "AccessDeniedException")
	}
	batch := must[*secretsmanager.BatchGetSecretValueOutput](t)(sm.BatchGetSecretValue(ctx, &secretsmanager.BatchGetSecretValueInput{
		Filters: []smtypes.Filter{{Key: smtypes.FilterNameStringTypeName, Values: []string{"app"}}}}))
	if len(batch.SecretValues) != 2 || len(batch.Errors) != 0 {
		t.Fatalf("BatchGetSecretValue by filter = %d values, %d errors; want only the 2 allowed", len(batch.SecretValues), len(batch.Errors))
	}
	batch = must[*secretsmanager.BatchGetSecretValueOutput](t)(sm.BatchGetSecretValue(ctx, &secretsmanager.BatchGetSecretValueInput{SecretIdList: []string{"app-a/prod/DB", "app-b/prod/DB"}}))
	if len(batch.SecretValues) != 1 || len(batch.Errors) != 1 || aws.ToString(batch.Errors[0].ErrorCode) != "AccessDeniedException" {
		t.Fatalf("BatchGetSecretValue by id = %+v", batch)
	}
	// Writes, other services and role chaining are not in the policy.
	_, err := sm.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{SecretId: aws.String("app-a/prod/DB"), SecretString: aws.String("x")})
	wantCode(t, err, "AccessDeniedException")
	_, err = sm.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: aws.String("app-a/prod/NEW"), SecretString: aws.String("x")})
	wantCode(t, err, "AccessDeniedException")
	_, err = k.Encrypt(ctx, &kms.EncryptInput{KeyId: aws.String("harness-default-key"), Plaintext: []byte("x")})
	wantCode(t, err, "AccessDeniedException")
	_, err = ps.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String("/x")})
	wantCode(t, err, "AccessDeniedException")
	open := mkRole("chain-target", "")
	_, err = st.AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: aws.String(open), RoleSessionName: aws.String("x")})
	wantCode(t, err, "AccessDenied")

	// A policy change applies to existing sessions at once.
	mkRole("app-a-prod", `{"Statement":[{"Effect":"Allow","Action":"secretsmanager:*","Resource":"arn:aws:secretsmanager:*:*:secret:app-a/*"}]}`)
	if got := strings.Join(listNames(sm), ","); got != "app-a/prod/API,app-a/prod/DB,app-a/staging/DB" {
		t.Fatalf("ListSecrets after widening = %s", got)
	}
	must[*secretsmanager.CreateSecretOutput](t)(sm.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: aws.String("app-a/prod/NEW"), SecretString: aws.String("x")}))
	_, err = sm.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: aws.String("app-b/prod/NEW"), SecretString: aws.String("x")})
	wantCode(t, err, "AccessDeniedException")

	// A role without a policy keeps the pre-2.7 account-wide access.
	_, legacy, _, _ := assume(open)
	if n := len(listNames(legacy)); n != 5 {
		t.Fatalf("unrestricted role lists %d secrets, want all 5", n)
	}

	// Deleting the role revokes its sessions.
	if err := h.st.DeleteIAMRole(ctx, harnessAccount, "app-a-prod"); err != nil {
		t.Fatal(err)
	}
	_, err = sm.ListSecrets(ctx, &secretsmanager.ListSecretsInput{})
	if err == nil {
		t.Fatal("a session of a deleted role still works")
	}
}
