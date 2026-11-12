package server

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"unicode"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

func TestSDKSecretsManager(t *testing.T) {
	h := newSDKHarness(t)
	ctx := context.Background()
	c := h.sm

	created := must[*secretsmanager.CreateSecretOutput](t)(c.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name:         aws.String("app/prod/db"),
		Description:  aws.String("database credentials"),
		SecretString: aws.String(`{"user":"app","password":"v1"}`),
		Tags:         []smtypes.Tag{{Key: aws.String("team"), Value: aws.String("payments")}},
	}))
	wantRequestID(t, created.ResultMetadata)
	v1 := aws.ToString(created.VersionId)

	t.Run("DescribeSecret and GetSecretValue", func(t *testing.T) {
		d := must[*secretsmanager.DescribeSecretOutput](t)(c.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String("app/prod/db")}))
		if d.CreatedDate == nil || aws.ToString(d.Description) != "database credentials" || len(d.Tags) != 1 || aws.ToString(d.Tags[0].Value) != "payments" {
			t.Fatalf("DescribeSecret = %+v", d)
		}
		if stages := d.VersionIdsToStages[v1]; len(stages) != 1 || stages[0] != "AWSCURRENT" {
			t.Fatalf("VersionIdsToStages = %v", d.VersionIdsToStages)
		}
		// By ARN as well as by name.
		g := must[*secretsmanager.GetSecretValueOutput](t)(c.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: created.ARN}))
		if aws.ToString(g.SecretString) != `{"user":"app","password":"v1"}` || g.CreatedDate == nil {
			t.Fatalf("GetSecretValue = %+v", g)
		}
		_, err := c.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String("app/missing")})
		wantCode(t, err, "ResourceNotFoundException")
		_, err = c.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: aws.String("app/prod/db"), SecretString: aws.String("x")})
		wantCode(t, err, "ResourceExistsException")
	})

	t.Run("versions and stages", func(t *testing.T) {
		put := must[*secretsmanager.PutSecretValueOutput](t)(c.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{SecretId: aws.String("app/prod/db"), SecretString: aws.String("v2")}))
		v2 := aws.ToString(put.VersionId)
		prev := must[*secretsmanager.GetSecretValueOutput](t)(c.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String("app/prod/db"), VersionStage: aws.String("AWSPREVIOUS")}))
		if aws.ToString(prev.VersionId) != v1 {
			t.Fatalf("AWSPREVIOUS = %s, want %s", aws.ToString(prev.VersionId), v1)
		}
		ids := must[*secretsmanager.ListSecretVersionIdsOutput](t)(c.ListSecretVersionIds(ctx, &secretsmanager.ListSecretVersionIdsInput{SecretId: aws.String("app/prod/db")}))
		if len(ids.Versions) != 2 {
			t.Fatalf("ListSecretVersionIds = %+v", ids.Versions)
		}
		// Roll back: move AWSCURRENT to v1.
		must[*secretsmanager.UpdateSecretVersionStageOutput](t)(c.UpdateSecretVersionStage(ctx, &secretsmanager.UpdateSecretVersionStageInput{
			SecretId: aws.String("app/prod/db"), VersionStage: aws.String("AWSCURRENT"), MoveToVersionId: aws.String(v1), RemoveFromVersionId: aws.String(v2),
		}))
		cur := must[*secretsmanager.GetSecretValueOutput](t)(c.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String("app/prod/db")}))
		if aws.ToString(cur.VersionId) != v1 {
			t.Fatalf("AWSCURRENT after rollback = %s", aws.ToString(cur.VersionId))
		}
		byID := must[*secretsmanager.GetSecretValueOutput](t)(c.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String("app/prod/db"), VersionId: aws.String(v2)}))
		if aws.ToString(byID.SecretString) != "v2" {
			t.Fatalf("GetSecretValue by VersionId = %q", aws.ToString(byID.SecretString))
		}
		_, err := c.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String("app/prod/db"), VersionStage: aws.String("NOPE")})
		wantCode(t, err, "ResourceNotFoundException")

		up := must[*secretsmanager.UpdateSecretOutput](t)(c.UpdateSecret(ctx, &secretsmanager.UpdateSecretInput{SecretId: aws.String("app/prod/db"), Description: aws.String("rotated"), SecretString: aws.String("v3")}))
		if aws.ToString(up.VersionId) == "" {
			t.Fatal("UpdateSecret with a value returned no VersionId")
		}
	})

	t.Run("tags", func(t *testing.T) {
		must[*secretsmanager.TagResourceOutput](t)(c.TagResource(ctx, &secretsmanager.TagResourceInput{SecretId: aws.String("app/prod/db"), Tags: []smtypes.Tag{{Key: aws.String("env"), Value: aws.String("prod")}}}))
		must[*secretsmanager.UntagResourceOutput](t)(c.UntagResource(ctx, &secretsmanager.UntagResourceInput{SecretId: aws.String("app/prod/db"), TagKeys: []string{"team"}}))
		d := must[*secretsmanager.DescribeSecretOutput](t)(c.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String("app/prod/db")}))
		if len(d.Tags) != 1 || aws.ToString(d.Tags[0].Key) != "env" {
			t.Fatalf("tags after tag/untag = %+v", d.Tags)
		}
	})

	t.Run("ListSecrets pagination and filters", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			in := &secretsmanager.CreateSecretInput{Name: aws.String(fmt.Sprintf("svc/item-%d", i)), SecretString: aws.String("x")}
			if i%2 == 0 {
				in.Tags = []smtypes.Tag{{Key: aws.String("even"), Value: aws.String("yes")}}
			}
			must[*secretsmanager.CreateSecretOutput](t)(c.CreateSecret(ctx, in))
		}
		list := func(in *secretsmanager.ListSecretsInput) []string {
			var names []string
			p := secretsmanager.NewListSecretsPaginator(c, in)
			for p.HasMorePages() {
				for _, s := range must[*secretsmanager.ListSecretsOutput](t)(p.NextPage(ctx)).SecretList {
					names = append(names, aws.ToString(s.Name))
				}
			}
			return names
		}
		all := list(&secretsmanager.ListSecretsInput{MaxResults: aws.Int32(2)})
		if len(all) != 6 || !sort.StringsAreSorted(all) {
			t.Fatalf("ListSecrets = %v", all)
		}
		byName := list(&secretsmanager.ListSecretsInput{MaxResults: aws.Int32(2), Filters: []smtypes.Filter{{Key: smtypes.FilterNameStringTypeName, Values: []string{"SVC/"}}}})
		if len(byName) != 5 {
			t.Fatalf("name filter = %v", byName)
		}
		byTag := list(&secretsmanager.ListSecretsInput{Filters: []smtypes.Filter{{Key: smtypes.FilterNameStringTypeTagKey, Values: []string{"even"}}}})
		if len(byTag) != 3 {
			t.Fatalf("tag-key filter = %v", byTag)
		}
		negated := list(&secretsmanager.ListSecretsInput{Filters: []smtypes.Filter{
			{Key: smtypes.FilterNameStringTypeName, Values: []string{"svc/"}},
			{Key: smtypes.FilterNameStringTypeTagKey, Values: []string{"!even"}},
		}})
		if len(negated) != 2 {
			t.Fatalf("negated tag-key filter = %v", negated)
		}
		_, err := c.ListSecrets(ctx, &secretsmanager.ListSecretsInput{NextToken: aws.String("forged")})
		wantCode(t, err, "InvalidNextTokenException")
	})

	t.Run("resource policy", func(t *testing.T) {
		must[*secretsmanager.CreateSecretOutput](t)(c.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: aws.String("locked"), SecretString: aws.String("x")}))
		deny := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`
		v := must[*secretsmanager.ValidateResourcePolicyOutput](t)(c.ValidateResourcePolicy(ctx, &secretsmanager.ValidateResourcePolicyInput{ResourcePolicy: aws.String(deny)}))
		if !v.PolicyValidationPassed {
			t.Fatal("ValidateResourcePolicy rejected a valid policy")
		}
		must[*secretsmanager.PutResourcePolicyOutput](t)(c.PutResourcePolicy(ctx, &secretsmanager.PutResourcePolicyInput{SecretId: aws.String("locked"), ResourcePolicy: aws.String(deny)}))
		got := must[*secretsmanager.GetResourcePolicyOutput](t)(c.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{SecretId: aws.String("locked")}))
		if !strings.Contains(aws.ToString(got.ResourcePolicy), "Deny") {
			t.Fatalf("GetResourcePolicy = %s", aws.ToString(got.ResourcePolicy))
		}
		_, err := c.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String("locked")})
		wantCode(t, err, "AccessDeniedException")
	})

	t.Run("delete and restore", func(t *testing.T) {
		must[*secretsmanager.CreateSecretOutput](t)(c.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: aws.String("doomed"), SecretString: aws.String("x")}))
		del := must[*secretsmanager.DeleteSecretOutput](t)(c.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{SecretId: aws.String("doomed"), RecoveryWindowInDays: aws.Int64(7)}))
		if del.DeletionDate == nil {
			t.Fatal("DeleteSecret returned no DeletionDate")
		}
		_, err := c.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String("doomed")})
		wantCode(t, err, "InvalidRequestException")
		has := func(include bool) bool {
			out := must[*secretsmanager.ListSecretsOutput](t)(c.ListSecrets(ctx, &secretsmanager.ListSecretsInput{IncludePlannedDeletion: aws.Bool(include), MaxResults: aws.Int32(100)}))
			for _, s := range out.SecretList {
				if aws.ToString(s.Name) == "doomed" {
					return true
				}
			}
			return false
		}
		if has(false) || !has(true) {
			t.Fatal("IncludePlannedDeletion not honoured")
		}
		must[*secretsmanager.RestoreSecretOutput](t)(c.RestoreSecret(ctx, &secretsmanager.RestoreSecretInput{SecretId: aws.String("doomed")}))
		must[*secretsmanager.GetSecretValueOutput](t)(c.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String("doomed")}))
		must[*secretsmanager.DeleteSecretOutput](t)(c.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{SecretId: aws.String("doomed"), ForceDeleteWithoutRecovery: aws.Bool(true)}))
		_, err = c.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String("doomed")})
		if code := apiCode(err); code != "ResourceNotFoundException" && code != "InvalidRequestException" {
			t.Fatalf("after force delete: %v", err)
		}
	})

	t.Run("rotation", func(t *testing.T) {
		must[*secretsmanager.CreateSecretOutput](t)(c.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: aws.String("rotating"), SecretString: aws.String("x")}))
		must[*secretsmanager.RotateSecretOutput](t)(c.RotateSecret(ctx, &secretsmanager.RotateSecretInput{
			SecretId: aws.String("rotating"), RotationRules: &smtypes.RotationRulesType{AutomaticallyAfterDays: aws.Int64(10)}, RotateImmediately: aws.Bool(false),
		}))
		d := must[*secretsmanager.DescribeSecretOutput](t)(c.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String("rotating")}))
		if !aws.ToBool(d.RotationEnabled) || d.NextRotationDate == nil {
			t.Fatalf("rotation not enabled: %+v", d)
		}
		must[*secretsmanager.CancelRotateSecretOutput](t)(c.CancelRotateSecret(ctx, &secretsmanager.CancelRotateSecretInput{SecretId: aws.String("rotating")}))
	})

	t.Run("BatchGetSecretValue", func(t *testing.T) {
		out := must[*secretsmanager.BatchGetSecretValueOutput](t)(c.BatchGetSecretValue(ctx, &secretsmanager.BatchGetSecretValueInput{SecretIdList: []string{"svc/item-0", "svc/item-1", "svc/nope"}}))
		if len(out.SecretValues) != 2 || len(out.Errors) != 1 || aws.ToString(out.Errors[0].ErrorCode) != "ResourceNotFoundException" {
			t.Fatalf("BatchGetSecretValue = %+v", out)
		}
		var names []string
		p := secretsmanager.NewBatchGetSecretValuePaginator(c, &secretsmanager.BatchGetSecretValueInput{
			Filters: []smtypes.Filter{{Key: smtypes.FilterNameStringTypeName, Values: []string{"svc/"}}}, MaxResults: aws.Int32(2),
		})
		for p.HasMorePages() {
			for _, v := range must[*secretsmanager.BatchGetSecretValueOutput](t)(p.NextPage(ctx)).SecretValues {
				if aws.ToString(v.SecretString) != "x" {
					t.Fatalf("value of %s = %q", aws.ToString(v.Name), aws.ToString(v.SecretString))
				}
				names = append(names, aws.ToString(v.Name))
			}
		}
		if len(names) != 5 {
			t.Fatalf("BatchGetSecretValue by filter = %v", names)
		}
		_, err := c.BatchGetSecretValue(ctx, &secretsmanager.BatchGetSecretValueInput{})
		wantCode(t, err, "InvalidParameterException")
	})

	t.Run("GetRandomPassword", func(t *testing.T) {
		def := must[*secretsmanager.GetRandomPasswordOutput](t)(c.GetRandomPassword(ctx, &secretsmanager.GetRandomPasswordInput{}))
		if len(aws.ToString(def.RandomPassword)) != 32 {
			t.Fatalf("default length = %d", len(aws.ToString(def.RandomPassword)))
		}
		p := aws.ToString(must[*secretsmanager.GetRandomPasswordOutput](t)(c.GetRandomPassword(ctx, &secretsmanager.GetRandomPasswordInput{
			PasswordLength: aws.Int64(40), ExcludePunctuation: aws.Bool(true), ExcludeCharacters: aws.String("0O1l"),
		})).RandomPassword)
		if len(p) != 40 || strings.ContainsAny(p, "0O1l") {
			t.Fatalf("password %q", p)
		}
		var upper, lower, digit bool
		for _, r := range p {
			switch {
			case unicode.IsUpper(r):
				upper = true
			case unicode.IsLower(r):
				lower = true
			case unicode.IsDigit(r):
				digit = true
			default:
				t.Fatalf("punctuation %q in %q", r, p)
			}
		}
		if !upper || !lower || !digit {
			t.Fatalf("RequireEachIncludedType not honoured: %q", p)
		}
		_, err := c.GetRandomPassword(ctx, &secretsmanager.GetRandomPasswordInput{PasswordLength: aws.Int64(5000)})
		wantCode(t, err, "InvalidParameterException")
	})
}
