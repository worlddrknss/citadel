package server

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

func TestReservedParameterName(t *testing.T) {
	for name, want := range map[string]bool{
		"/aws/x": true, "/AWS": true, "/awsKey": true, "/SSM-config": true, "/ssm/a/b": true, "/Ssmx": true,
		"/app/aws": false, "/app/ssm/x": false, "/a-aws": false, "/my-ssm": false, "/as": false,
	} {
		if got := reservedParameterName(name); got != want {
			t.Errorf("reservedParameterName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestParameterNameLimits(t *testing.T) {
	// AWS's example: arn:aws:ssm:us-east-2:111222333444:parameter/ExampleParameterName
	// is 65 characters, so a name may be 1011-44 characters long there.
	if got := maxParameterNameLength("us-east-2", "111222333444"); got != 1011-44 {
		t.Fatalf("maxParameterNameLength = %d", got)
	}
	if len("arn:aws:ssm:us-east-2:111222333444:parameter/ExampleParameterName") != 65 {
		t.Fatal("ARN arithmetic")
	}
	levels := func(n int) string { return strings.Repeat("/a", n) }
	if _, err := normalizeParameterName(levels(15)); err != nil {
		t.Fatalf("15 levels: %v", err)
	}
	_, err := normalizeParameterName(levels(16))
	if typ, msg := ssmNameErrorParts(err); typ != "HierarchyLevelLimitExceededException" || !strings.Contains(msg, "maximum of 15 levels") {
		t.Fatalf("16 levels = %q %q", typ, msg)
	}
	_, err = normalizeParameterName("/" + strings.Repeat("a", 2048))
	if typ, msg := ssmNameErrorParts(err); typ != "ValidationException" || !strings.Contains(msg, "2048") {
		t.Fatalf("2049 characters = %q %q", typ, msg)
	}
}

// TestSDKSSMParameterNameRules sends refused names through the AWS SDK.
func TestSDKSSMParameterNameRules(t *testing.T) {
	h := newSDKHarness(t)
	ctx := context.Background()
	put := func(name string) error {
		_, err := h.ssm.PutParameter(ctx, &ssm.PutParameterInput{Name: aws.String(name), Value: aws.String("v"), Type: ssmtypes.ParameterTypeString})
		return err
	}
	for _, name := range []string{"awsKey", "/aws/x", "SSM-config", "/Ssm/a"} {
		err := put(name)
		wantCode(t, err, "ValidationException")
		if !strings.Contains(err.Error(), `can't be prefixed with "aws" or "ssm" (case-insensitive)`) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	err := put(strings.Repeat("/a", 16))
	wantCode(t, err, "HierarchyLevelLimitExceededException")

	region, acct := h.st.DeploymentIdentity()
	limit := maxParameterNameLength(region, acct)
	if err := put("/" + strings.Repeat("n", limit-1)); err != nil {
		t.Fatalf("name at the limit: %v", err)
	}
	err = put("/" + strings.Repeat("n", limit))
	wantCode(t, err, "ValidationException")
	if !strings.Contains(err.Error(), "1011") {
		t.Fatalf("too long: %v", err)
	}
	// Names that merely contain aws or ssm below the first level are fine.
	if err := put("/app/aws/ssm"); err != nil {
		t.Fatal(err)
	}
}

func TestNativeParameterNameRules(t *testing.T) {
	e := newSecretsTestEnv(t)
	for _, tc := range []struct{ name, want string }{
		{"/aws/x", msgParameterNameReserved},
		{"ssmThing", msgParameterNameReserved},
		{strings.Repeat("/a", 16), msgParameterHierarchy},
		{"/" + strings.Repeat("n", 2000), "Parameter names can be at most"},
	} {
		c, b := e.do("alice", "POST", "/v1/parameters", map[string]any{"name": tc.name, "type": "String", "value": "v"})
		e.want(c, 400, b, tc.name)
		if msg, _ := b["message"].(string); !strings.Contains(msg, tc.want) {
			t.Fatalf("%s: message %v, want %q", tc.name, b, tc.want)
		}
	}
	c, b := e.do("alice", "GET", "/v1/parameters", nil)
	e.want(c, 200, b, "list")
	limits, _ := b["limits"].(map[string]any)
	if limits["maxHierarchyLevels"] != float64(15) || limits["nameMaxLength"].(float64) < 900 {
		t.Fatalf("limits = %v", b["limits"])
	}
}
