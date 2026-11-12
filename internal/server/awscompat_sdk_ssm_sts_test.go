package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/worlddrknss/citadel/internal/store"
)

func TestSDKSSM(t *testing.T) {
	h := newSDKHarness(t)
	ctx := context.Background()
	c := h.ssm
	put := func(name, value string, typ ssmtypes.ParameterType, tags ...ssmtypes.Tag) {
		t.Helper()
		out := must[*ssm.PutParameterOutput](t)(c.PutParameter(ctx, &ssm.PutParameterInput{Name: aws.String(name), Value: aws.String(value), Type: typ, Tags: tags}))
		wantRequestID(t, out.ResultMetadata)
	}
	put("/app/prod/db/password", "s3cret", ssmtypes.ParameterTypeSecureString, ssmtypes.Tag{Key: aws.String("env"), Value: aws.String("prod")})
	put("/app/prod/db/host", "db.internal", ssmtypes.ParameterTypeString)
	put("/app/prod/hosts", "a,b,c", ssmtypes.ParameterTypeStringList)
	put("/app/prod/feature", "on", ssmtypes.ParameterTypeString, ssmtypes.Tag{Key: aws.String("env"), Value: aws.String("prod")})
	put("/app/dev/feature", "off", ssmtypes.ParameterTypeString, ssmtypes.Tag{Key: aws.String("env"), Value: aws.String("dev")})
	put("/app/prod/a", "1", ssmtypes.ParameterTypeString)
	put("/app/prod/b", "2", ssmtypes.ParameterTypeString)
	put("toplevel", "t", ssmtypes.ParameterTypeString)

	t.Run("GetParameter, decryption and selectors", func(t *testing.T) {
		enc := must[*ssm.GetParameterOutput](t)(c.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String("/app/prod/db/password")}))
		if aws.ToString(enc.Parameter.Value) == "s3cret" {
			t.Fatal("SecureString returned in clear without WithDecryption")
		}
		dec := must[*ssm.GetParameterOutput](t)(c.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String("/app/prod/db/password"), WithDecryption: aws.Bool(true)}))
		if aws.ToString(dec.Parameter.Value) != "s3cret" || dec.Parameter.LastModifiedDate == nil || !strings.HasPrefix(aws.ToString(dec.Parameter.ARN), "arn:aws:ssm:") {
			t.Fatalf("GetParameter = %+v", dec.Parameter)
		}
		_, err := c.PutParameter(ctx, &ssm.PutParameterInput{Name: aws.String("/app/prod/a"), Value: aws.String("x"), Type: ssmtypes.ParameterTypeString})
		wantCode(t, err, "ParameterAlreadyExists")
		v2 := must[*ssm.PutParameterOutput](t)(c.PutParameter(ctx, &ssm.PutParameterInput{Name: aws.String("/app/prod/a"), Value: aws.String("1b"), Overwrite: aws.Bool(true)}))
		if v2.Version != 2 {
			t.Fatalf("overwrite version = %d", v2.Version)
		}
		old := must[*ssm.GetParameterOutput](t)(c.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String("/app/prod/a:1")}))
		if aws.ToString(old.Parameter.Value) != "1" || aws.ToString(old.Parameter.Selector) != ":1" {
			t.Fatalf("version selector = %+v", old.Parameter)
		}
		_, err = c.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String("/app/prod/a:9")})
		wantCode(t, err, "ParameterVersionNotFound")
		_, err = c.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String("/app/none")})
		wantCode(t, err, "ParameterNotFound")
		_, err = c.PutParameter(ctx, &ssm.PutParameterInput{Name: aws.String("/app/x"), Value: aws.String("x"), Overwrite: aws.Bool(true), Tags: []ssmtypes.Tag{{Key: aws.String("k"), Value: aws.String("v")}}})
		wantCode(t, err, "ValidationException")
	})

	t.Run("GetParameters", func(t *testing.T) {
		out := must[*ssm.GetParametersOutput](t)(c.GetParameters(ctx, &ssm.GetParametersInput{Names: []string{"/app/prod/db/host", "/app/missing", "toplevel"}}))
		if len(out.Parameters) != 2 || len(out.InvalidParameters) != 1 || out.InvalidParameters[0] != "/app/missing" {
			t.Fatalf("GetParameters = %+v", out)
		}
	})

	byPath := func(in *ssm.GetParametersByPathInput) []string {
		t.Helper()
		var names []string
		p := ssm.NewGetParametersByPathPaginator(c, in)
		for p.HasMorePages() {
			for _, prm := range must[*ssm.GetParametersByPathOutput](t)(p.NextPage(ctx)).Parameters {
				names = append(names, aws.ToString(prm.Name))
			}
		}
		return names
	}

	t.Run("GetParametersByPath recursion and pagination", func(t *testing.T) {
		rec := byPath(&ssm.GetParametersByPathInput{Path: aws.String("/app/prod"), Recursive: aws.Bool(true), MaxResults: aws.Int32(2)})
		if len(rec) != 6 {
			t.Fatalf("recursive = %v", rec)
		}
		one := byPath(&ssm.GetParametersByPathInput{Path: aws.String("/app/prod/"), MaxResults: aws.Int32(2)})
		if len(one) != 4 {
			t.Fatalf("one level = %v", one)
		}
		root := byPath(&ssm.GetParametersByPathInput{Path: aws.String("/"), Recursive: aws.Bool(true), MaxResults: aws.Int32(3)})
		if len(root) != 8 {
			t.Fatalf("root = %v", root)
		}
		top := byPath(&ssm.GetParametersByPathInput{Path: aws.String("/")})
		if len(top) != 1 || top[0] != "/toplevel" {
			t.Fatalf("root one level = %v", top)
		}
		secure := byPath(&ssm.GetParametersByPathInput{Path: aws.String("/app"), Recursive: aws.Bool(true), WithDecryption: aws.Bool(true), ParameterFilters: []ssmtypes.ParameterStringFilter{{Key: aws.String("Type"), Values: []string{"SecureString"}}}})
		if len(secure) != 1 {
			t.Fatalf("Type filter = %v", secure)
		}
		_, err := c.GetParametersByPath(ctx, &ssm.GetParametersByPathInput{Path: aws.String("/app"), MaxResults: aws.Int32(11)})
		wantCode(t, err, "ValidationException")
	})

	t.Run("DescribeParameters with ParameterFilters", func(t *testing.T) {
		describe := func(filters ...ssmtypes.ParameterStringFilter) []string {
			var names []string
			p := ssm.NewDescribeParametersPaginator(c, &ssm.DescribeParametersInput{ParameterFilters: filters, MaxResults: aws.Int32(2)})
			for p.HasMorePages() {
				for _, m := range must[*ssm.DescribeParametersOutput](t)(p.NextPage(ctx)).Parameters {
					names = append(names, aws.ToString(m.Name))
				}
			}
			return names
		}
		if all := describe(); len(all) != 8 {
			t.Fatalf("all = %v", all)
		}
		if got := describe(ssmtypes.ParameterStringFilter{Key: aws.String("Name"), Option: aws.String("BeginsWith"), Values: []string{"/app/prod/db"}}); len(got) != 2 {
			t.Fatalf("Name BeginsWith = %v", got)
		}
		if got := describe(ssmtypes.ParameterStringFilter{Key: aws.String("Path"), Option: aws.String("OneLevel"), Values: []string{"/app/prod"}}); len(got) != 4 {
			t.Fatalf("Path OneLevel = %v", got)
		}
		if got := describe(ssmtypes.ParameterStringFilter{Key: aws.String("Type"), Values: []string{"StringList"}}); len(got) != 1 {
			t.Fatalf("Type = %v", got)
		}
		if got := describe(ssmtypes.ParameterStringFilter{Key: aws.String("tag:env"), Values: []string{"prod"}}); len(got) != 2 {
			t.Fatalf("tag:env = %v", got)
		}
		_, err := c.DescribeParameters(ctx, &ssm.DescribeParametersInput{ParameterFilters: []ssmtypes.ParameterStringFilter{{Key: aws.String("Bogus"), Values: []string{"x"}}}})
		wantCode(t, err, "ValidationException")
	})

	t.Run("history and labels", func(t *testing.T) {
		lbl := must[*ssm.LabelParameterVersionOutput](t)(c.LabelParameterVersion(ctx, &ssm.LabelParameterVersionInput{Name: aws.String("/app/prod/a"), ParameterVersion: aws.Int64(1), Labels: []string{"stable", "aws-reserved"}}))
		if len(lbl.InvalidLabels) != 1 || lbl.InvalidLabels[0] != "aws-reserved" {
			t.Fatalf("InvalidLabels = %v", lbl.InvalidLabels)
		}
		hist := must[*ssm.GetParameterHistoryOutput](t)(c.GetParameterHistory(ctx, &ssm.GetParameterHistoryInput{Name: aws.String("/app/prod/a")}))
		if len(hist.Parameters) != 2 || len(hist.Parameters[0].Labels) != 1 || hist.Parameters[0].Labels[0] != "stable" {
			t.Fatalf("history = %+v", hist.Parameters)
		}
		byLabel := must[*ssm.GetParameterOutput](t)(c.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String("/app/prod/a:stable")}))
		if aws.ToString(byLabel.Parameter.Value) != "1" {
			t.Fatalf("label selector value = %q", aws.ToString(byLabel.Parameter.Value))
		}
		_, err := c.LabelParameterVersion(ctx, &ssm.LabelParameterVersionInput{Name: aws.String("/app/prod/a"), ParameterVersion: aws.Int64(42), Labels: []string{"x"}})
		wantCode(t, err, "ParameterVersionNotFound")
	})

	t.Run("tags", func(t *testing.T) {
		must[*ssm.AddTagsToResourceOutput](t)(c.AddTagsToResource(ctx, &ssm.AddTagsToResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingParameter, ResourceId: aws.String("/app/prod/b"), Tags: []ssmtypes.Tag{{Key: aws.String("owner"), Value: aws.String("me")}, {Key: aws.String("tmp"), Value: aws.String("1")}}}))
		must[*ssm.RemoveTagsFromResourceOutput](t)(c.RemoveTagsFromResource(ctx, &ssm.RemoveTagsFromResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingParameter, ResourceId: aws.String("/app/prod/b"), TagKeys: []string{"tmp"}}))
		tags := must[*ssm.ListTagsForResourceOutput](t)(c.ListTagsForResource(ctx, &ssm.ListTagsForResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingParameter, ResourceId: aws.String("/app/prod/b")}))
		if len(tags.TagList) != 1 || aws.ToString(tags.TagList[0].Key) != "owner" {
			t.Fatalf("tags = %+v", tags.TagList)
		}
		_, err := c.ListTagsForResource(ctx, &ssm.ListTagsForResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingParameter, ResourceId: aws.String("/nope")})
		wantCode(t, err, "InvalidResourceId")
	})

	t.Run("delete", func(t *testing.T) {
		must[*ssm.DeleteParameterOutput](t)(c.DeleteParameter(ctx, &ssm.DeleteParameterInput{Name: aws.String("toplevel")}))
		_, err := c.DeleteParameter(ctx, &ssm.DeleteParameterInput{Name: aws.String("toplevel")})
		wantCode(t, err, "ParameterNotFound")
		out := must[*ssm.DeleteParametersOutput](t)(c.DeleteParameters(ctx, &ssm.DeleteParametersInput{Names: []string{"/app/prod/a", "/app/prod/nope"}}))
		if len(out.DeletedParameters) != 1 || len(out.InvalidParameters) != 1 {
			t.Fatalf("DeleteParameters = %+v", out)
		}
	})
}

// fakeOIDCIssuer serves discovery and a JWKS for one ES256 key and mints
// tokens signed by it.
type fakeOIDCIssuer struct {
	srv  *httptest.Server
	key  *ecdsa.PrivateKey
	hits atomic.Int64 // requests the issuer has served
}

func newFakeOIDCIssuer(t *testing.T) *fakeOIDCIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	iss := &fakeOIDCIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": iss.srv.URL, "jwks_uri": iss.srv.URL + "/keys"})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		b := func(v []byte) string { return base64.RawURLEncoding.EncodeToString(v) }
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
			"x": b(key.PublicKey.X.FillBytes(make([]byte, 32))), "y": b(key.PublicKey.Y.FillBytes(make([]byte, 32))),
		}}})
	})
	iss.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		iss.hits.Add(1)
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(iss.srv.Close)
	return iss
}

func (iss *fakeOIDCIssuer) token(t *testing.T, sub, aud string) string {
	t.Helper()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	input := enc(map[string]string{"alg": "ES256", "kid": "k1", "typ": "JWT"}) + "." +
		enc(map[string]any{"iss": iss.srv.URL, "sub": sub, "aud": aud, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, iss.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

type staticToken string

func (s staticToken) GetIdentityToken() ([]byte, error) { return []byte(s), nil }

func TestSDKSTS(t *testing.T) {
	h := newSDKHarness(t)
	ctx := context.Background()

	id := must[*sts.GetCallerIdentityOutput](t)(h.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}))
	wantRequestID(t, id.ResultMetadata)
	if aws.ToString(id.Account) != harnessAccount || !strings.Contains(aws.ToString(id.Arn), ":user/") {
		t.Fatalf("GetCallerIdentity = %s %s", aws.ToString(id.Account), aws.ToString(id.Arn))
	}

	t.Run("AssumeRole and use the temporary credentials", func(t *testing.T) {
		roleARN := "arn:aws:iam::" + harnessAccount + ":role/deployer"
		if err := h.st.CreateIAMRole(ctx, store.IAMRole{RoleARN: roleARN, AccountID: harnessAccount, RoleName: "deployer", Trust: store.TrustPolicy{Type: trustTypeAccount, Principals: []string{harnessAccount}}, MaxSessionSecs: 3600}); err != nil {
			t.Fatal(err)
		}
		out := must[*sts.AssumeRoleOutput](t)(h.sts.AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: aws.String(roleARN), RoleSessionName: aws.String("ci")}))
		cr := out.Credentials
		if !strings.HasPrefix(aws.ToString(cr.AccessKeyId), "ASIA") || cr.Expiration == nil || !strings.Contains(aws.ToString(out.AssumedRoleUser.Arn), "assumed-role/deployer/ci") {
			t.Fatalf("AssumeRole = %+v", out)
		}
		k, _, _, s := h.clients(credentials.NewStaticCredentialsProvider(aws.ToString(cr.AccessKeyId), aws.ToString(cr.SecretAccessKey), aws.ToString(cr.SessionToken)))
		tid := must[*sts.GetCallerIdentityOutput](t)(s.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}))
		if aws.ToString(tid.Account) != harnessAccount || !strings.Contains(aws.ToString(tid.Arn), "assumed-role") {
			t.Fatalf("temporary identity = %s", aws.ToString(tid.Arn))
		}
		must[*kms.EncryptOutput](t)(k.Encrypt(ctx, &kms.EncryptInput{KeyId: aws.String("harness-default-key"), Plaintext: []byte("x")}))

		// The secret alone, without its session token, is not enough.
		_, _, _, bad := h.clients(credentials.NewStaticCredentialsProvider(aws.ToString(cr.AccessKeyId), aws.ToString(cr.SecretAccessKey), ""))
		_, err := bad.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		wantCode(t, err, "InvalidClientTokenId")
		_, err = h.sts.AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: aws.String("arn:aws:iam::" + harnessAccount + ":role/none"), RoleSessionName: aws.String("x")})
		wantCode(t, err, "NoSuchEntity")
	})

	t.Run("AssumeRoleWithWebIdentity via the SDK credential provider", func(t *testing.T) {
		iss := newFakeOIDCIssuer(t)
		if err := h.st.CreateOIDCProvider(ctx, store.OIDCProvider{ProviderARN: "arn:aws:iam::" + harnessAccount + ":oidc-provider/fake", AccountID: harnessAccount, URL: iss.srv.URL}); err != nil {
			t.Fatal(err)
		}
		roleARN := "arn:aws:iam::" + harnessAccount + ":role/workload"
		if err := h.st.CreateIAMRole(ctx, store.IAMRole{RoleARN: roleARN, AccountID: harnessAccount, RoleName: "workload", MaxSessionSecs: 3600, Trust: store.TrustPolicy{
			Type: trustTypeOIDC, ProviderURL: iss.srv.URL, Audiences: []string{"sts.amazonaws.com"}, Subjects: []string{"system:serviceaccount:app:*"},
		}}); err != nil {
			t.Fatal(err)
		}
		// The same provider IRSA / EKS Pod Identity style clients use.
		provider := stscreds.NewWebIdentityRoleProvider(h.sts, roleARN, staticToken(iss.token(t, "system:serviceaccount:app:api", "sts.amazonaws.com")))
		_, _, _, s := h.clients(aws.NewCredentialsCache(provider))
		tid := must[*sts.GetCallerIdentityOutput](t)(s.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}))
		if aws.ToString(tid.Account) != harnessAccount {
			t.Fatalf("web identity caller = %s", aws.ToString(tid.Arn))
		}
		_, err := h.sts.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{RoleArn: aws.String(roleARN), RoleSessionName: aws.String("x"), WebIdentityToken: aws.String(iss.token(t, "system:serviceaccount:other:api", "sts.amazonaws.com"))})
		wantCode(t, err, "AccessDenied")
		_, err = h.sts.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{RoleArn: aws.String(roleARN), RoleSessionName: aws.String("x"), WebIdentityToken: aws.String(iss.token(t, "system:serviceaccount:app:api", "wrong-aud"))})
		wantCode(t, err, "AccessDenied")

		// A forged token naming another issuer is refused without Citadel
		// ever contacting that issuer (no request forgery to arbitrary URLs).
		attacker := newFakeOIDCIssuer(t)
		_, err = h.sts.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{RoleArn: aws.String(roleARN), RoleSessionName: aws.String("x"), WebIdentityToken: aws.String(attacker.token(t, "system:serviceaccount:app:api", "sts.amazonaws.com"))})
		wantCode(t, err, "AccessDenied")
		if n := attacker.hits.Load(); n != 0 {
			t.Fatalf("Citadel made %d request(s) to an untrusted issuer named in an unverified token", n)
		}
	})
}

// TestAWSClientRequestShapes replays the JSON that Vault's awskms seal
// (aws-sdk-go v1) and External Secrets Operator send, including members
// Citadel does not model, signed with the SDK's SigV4 signer and posted to
// "/" exactly as those clients do.
func TestAWSClientRequestShapes(t *testing.T) {
	h := newSDKHarness(t)
	signer := v4.NewSigner()
	creds := aws.Credentials{AccessKeyID: harnessAccessKey, SecretAccessKey: harnessSecret}
	call := func(service, target string, body any) (int, map[string]any) {
		t.Helper()
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		req.Header.Set("X-Amz-Target", target)
		req.Header.Set("User-Agent", "aws-sdk-go/1.55.5 (go1.22; linux; amd64)")
		sum := sha256.Sum256(raw)
		if err := signer.SignHTTP(context.Background(), creds, req, hex.EncodeToString(sum[:]), service, harnessRegion, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		resp, err := h.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		if resp.Header.Get("x-amzn-RequestId") == "" {
			t.Fatalf("%s: no x-amzn-RequestId", target)
		}
		var out map[string]any
		_ = json.Unmarshal(data, &out)
		return resp.StatusCode, out
	}
	ok := func(service, target string, body any) map[string]any {
		t.Helper()
		code, out := call(service, target, body)
		if code != http.StatusOK {
			t.Fatalf("%s: status %d body %v", target, code, out)
		}
		return out
	}

	t.Run("Vault awskms seal", func(t *testing.T) {
		ec := map[string]string{"vault": "seal"}
		ok("kms", "TrentService.DescribeKey", map[string]any{"KeyId": "harness-default-key"})
		enc := ok("kms", "TrentService.Encrypt", map[string]any{
			"KeyId": "arn:aws:kms:" + harnessRegion + ":" + harnessAccount + ":key/harness-default-key", "Plaintext": base64.StdEncoding.EncodeToString([]byte("root key")),
			"EncryptionContext": ec, "GrantTokens": []string{},
		})
		dec := ok("kms", "TrentService.Decrypt", map[string]any{"CiphertextBlob": enc["CiphertextBlob"], "EncryptionContext": ec, "KeyId": "harness-default-key", "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"})
		if p, _ := base64.StdEncoding.DecodeString(fmt.Sprint(dec["Plaintext"])); string(p) != "root key" {
			t.Fatalf("Vault unseal round trip = %q", p)
		}
	})

	t.Run("External Secrets Operator", func(t *testing.T) {
		ok("secretsmanager", "secretsmanager.CreateSecret", map[string]any{"Name": "eso/app", "SecretString": `{"k":"v"}`, "ClientRequestToken": "11111111-2222-3333-4444-555555555555"})
		got := ok("secretsmanager", "secretsmanager.GetSecretValue", map[string]any{"SecretId": "eso/app", "VersionStage": "AWSCURRENT"})
		if got["SecretString"] != `{"k":"v"}` {
			t.Fatalf("ESO GetSecretValue = %v", got)
		}
		ok("secretsmanager", "secretsmanager.DescribeSecret", map[string]any{"SecretId": "eso/app"})
		list := ok("secretsmanager", "secretsmanager.ListSecrets", map[string]any{"Filters": []map[string]any{{"Key": "name", "Values": []string{"eso/"}}}, "MaxResults": 100, "SortOrder": "asc", "IncludePlannedDeletion": false})
		if l, _ := list["SecretList"].([]any); len(l) != 1 {
			t.Fatalf("ESO find = %v", list)
		}
		ok("ssm", "AmazonSSM.PutParameter", map[string]any{"Name": "/eso/p", "Value": "v", "Type": "SecureString", "Overwrite": true, "Tier": "Standard", "DataType": "text"})
		p := ok("ssm", "AmazonSSM.GetParameter", map[string]any{"Name": "/eso/p", "WithDecryption": true})
		if prm, _ := p["Parameter"].(map[string]any); prm["Value"] != "v" {
			t.Fatalf("ESO GetParameter = %v", p)
		}
		ok("ssm", "AmazonSSM.GetParametersByPath", map[string]any{"Path": "/eso", "Recursive": true, "WithDecryption": true})
		ok("ssm", "AmazonSSM.DescribeParameters", map[string]any{"ParameterFilters": []map[string]any{{"Key": "Name", "Option": "BeginsWith", "Values": []string{"/eso"}}}})
	})

	t.Run("unknown members are ignored, errors carry RequestId", func(t *testing.T) {
		ok("kms", "TrentService.ListKeys", map[string]any{"Limit": 10, "SomeFutureMember": map[string]any{"x": 1}})
		code, out := call("kms", "TrentService.DescribeKey", map[string]any{"KeyId": "missing"})
		if code != http.StatusBadRequest || out["__type"] != "NotFoundException" || out["RequestId"] == nil {
			t.Fatalf("missing key = %d %v", code, out)
		}
	})
}
