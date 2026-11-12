package server

// AWS compatibility harness: the real aws-sdk-go-v2 clients talk to Citadel
// (memory store, static access key) over an httptest server, through a
// custom endpoint resolver. A response the SDK cannot deserialize — an RFC
// 3339 timestamp where it expects epoch seconds, a missing member, a wrong
// error code — fails here exactly as it would for Terraform, Vault or ESO.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	smithyendpoints "github.com/aws/smithy-go/endpoints"
	"github.com/aws/smithy-go/middleware"

	"github.com/worlddrknss/citadel/internal/config"
	"github.com/worlddrknss/citadel/internal/store/memory"
)

const (
	harnessAccount   = "123456789012"
	harnessRegion    = "us-east-1"
	harnessAccessKey = "AKIACITADELHARNESS01"
	harnessSecret    = "citadel-harness-secret-0123456789abcdef"
)

// fixedEndpoint is a custom EndpointResolverV2 for any service: every
// operation resolves to the test server.
type fixedEndpoint[P any] struct{ u url.URL }

func (f fixedEndpoint[P]) ResolveEndpoint(context.Context, P) (smithyendpoints.Endpoint, error) {
	return smithyendpoints.Endpoint{URI: f.u}, nil
}

type sdkHarness struct {
	srv   *httptest.Server
	st    *memory.Store
	creds aws.CredentialsProvider
	kms   *kms.Client
	sm    *secretsmanager.Client
	ssm   *ssm.Client
	sts   *sts.Client
}

func newSDKHarness(t *testing.T) *sdkHarness {
	t.Helper()
	defaultKey := sampleKey(7)
	defaultKey.ID = "harness-default-key"
	defaultKey.ARN = "arn:aws:kms:" + harnessRegion + ":" + harnessAccount + ":key/" + defaultKey.ID
	st := &memory.Store{DefaultKey: defaultKey, Region: harnessRegion, AccountID: harnessAccount}
	s := &Server{cfg: config.Config{ExpectedAccessKey: harnessAccessKey, SecretAccessKey: harnessSecret}, store: st}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	h := &sdkHarness{srv: srv, st: st, creds: credentials.NewStaticCredentialsProvider(harnessAccessKey, harnessSecret, "")}
	h.kms, h.sm, h.ssm, h.sts = h.clients(h.creds)
	return h
}

// clients builds every service client for the given credentials.
func (h *sdkHarness) clients(creds aws.CredentialsProvider) (*kms.Client, *secretsmanager.Client, *ssm.Client, *sts.Client) {
	u, _ := url.Parse(h.srv.URL)
	cfg := aws.Config{
		Region:      harnessRegion,
		Credentials: creds,
		HTTPClient:  h.srv.Client(),
		Retryer:     func() aws.Retryer { return aws.NopRetryer{} },
	}
	return kms.NewFromConfig(cfg, func(o *kms.Options) { o.EndpointResolverV2 = fixedEndpoint[kms.EndpointParameters]{*u} }),
		secretsmanager.NewFromConfig(cfg, func(o *secretsmanager.Options) {
			o.EndpointResolverV2 = fixedEndpoint[secretsmanager.EndpointParameters]{*u}
		}),
		ssm.NewFromConfig(cfg, func(o *ssm.Options) { o.EndpointResolverV2 = fixedEndpoint[ssm.EndpointParameters]{*u} }),
		sts.NewFromConfig(cfg, func(o *sts.Options) { o.EndpointResolverV2 = fixedEndpoint[sts.EndpointParameters]{*u} })
}

// apiCode returns the AWS error code of err ("" for nil or non-API errors).
func apiCode(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return ""
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	if got := apiCode(err); got != code {
		t.Fatalf("error code = %q (err=%v), want %q", got, err, code)
	}
	var re *awshttp.ResponseError
	if !errors.As(err, &re) || re.ServiceRequestID() == "" {
		t.Fatalf("error %v carries no x-amzn-RequestId", err)
	}
}

func wantRequestID(t *testing.T, md middleware.Metadata) {
	t.Helper()
	if id, ok := awsmiddleware.GetRequestIDMetadata(md); !ok || id == "" {
		t.Fatal("response carries no x-amzn-RequestId")
	}
}

func must[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return v
	}
}

func TestSDKKMS(t *testing.T) {
	h := newSDKHarness(t)
	ctx := context.Background()
	c := h.kms

	created := must[*kms.CreateKeyOutput](t)(c.CreateKey(ctx, &kms.CreateKeyInput{Description: aws.String("harness key")}))
	wantRequestID(t, created.ResultMetadata)
	keyID := aws.ToString(created.KeyMetadata.KeyId)
	keyARN := aws.ToString(created.KeyMetadata.Arn)
	if created.KeyMetadata.CreationDate == nil || created.KeyMetadata.CreationDate.IsZero() || created.KeyMetadata.KeyState != kmstypes.KeyStateEnabled {
		t.Fatalf("CreateKey metadata = %+v", created.KeyMetadata)
	}
	if aws.ToString(created.KeyMetadata.AWSAccountId) != harnessAccount {
		t.Fatalf("AWSAccountId = %q", aws.ToString(created.KeyMetadata.AWSAccountId))
	}

	t.Run("DescribeKey by id, ARN and alias", func(t *testing.T) {
		must[*kms.CreateAliasOutput](t)(c.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String("alias/harness"), TargetKeyId: aws.String(keyID)}))
		for _, id := range []string{keyID, keyARN, "alias/harness", "arn:aws:kms:" + harnessRegion + ":" + harnessAccount + ":alias/harness"} {
			out := must[*kms.DescribeKeyOutput](t)(c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(id)}))
			if aws.ToString(out.KeyMetadata.KeyId) != keyID {
				t.Fatalf("DescribeKey(%s) = %s", id, aws.ToString(out.KeyMetadata.KeyId))
			}
		}
		_, err := c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String("00000000-0000-0000-0000-000000000000")})
		wantCode(t, err, "NotFoundException")
	})

	t.Run("Encrypt and Decrypt with encryption context", func(t *testing.T) {
		ec := map[string]string{"app": "harness", "env": "test"}
		enc := must[*kms.EncryptOutput](t)(c.Encrypt(ctx, &kms.EncryptInput{KeyId: aws.String("alias/harness"), Plaintext: []byte("top secret"), EncryptionContext: ec, GrantTokens: []string{"ignored"}}))
		if aws.ToString(enc.KeyId) != keyARN || enc.EncryptionAlgorithm != kmstypes.EncryptionAlgorithmSpecSymmetricDefault {
			t.Fatalf("Encrypt KeyId=%s alg=%s", aws.ToString(enc.KeyId), enc.EncryptionAlgorithm)
		}
		dec := must[*kms.DecryptOutput](t)(c.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: enc.CiphertextBlob, EncryptionContext: ec, KeyId: aws.String(keyARN)}))
		if string(dec.Plaintext) != "top secret" || aws.ToString(dec.KeyId) != keyARN {
			t.Fatalf("Decrypt = %q key %s", dec.Plaintext, aws.ToString(dec.KeyId))
		}
		_, err := c.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: enc.CiphertextBlob, EncryptionContext: map[string]string{"app": "other"}})
		wantCode(t, err, "InvalidCiphertextException")
		_, err = c.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: enc.CiphertextBlob, EncryptionContext: ec, KeyId: aws.String("harness-default-key")})
		wantCode(t, err, "IncorrectKeyException")
		_, err = c.Encrypt(ctx, &kms.EncryptInput{KeyId: aws.String(keyID), Plaintext: []byte("x"), DryRun: aws.Bool(true)})
		wantCode(t, err, "DryRunOperationException")
		_, err = c.Encrypt(ctx, &kms.EncryptInput{KeyId: aws.String(keyID), Plaintext: []byte("x"), EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecRsaesOaepSha256})
		wantCode(t, err, "InvalidKeyUsageException")
	})

	t.Run("GenerateDataKey variants and ReEncrypt", func(t *testing.T) {
		ec := map[string]string{"purpose": "dek"}
		dk := must[*kms.GenerateDataKeyOutput](t)(c.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{KeyId: aws.String(keyID), KeySpec: kmstypes.DataKeySpecAes256, EncryptionContext: ec}))
		if len(dk.Plaintext) != 32 {
			t.Fatalf("data key length %d", len(dk.Plaintext))
		}
		dec := must[*kms.DecryptOutput](t)(c.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: dk.CiphertextBlob, EncryptionContext: ec}))
		if !bytes.Equal(dec.Plaintext, dk.Plaintext) {
			t.Fatal("decrypted data key differs")
		}
		n := must[*kms.GenerateDataKeyOutput](t)(c.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{KeyId: aws.String(keyID), NumberOfBytes: aws.Int32(64)}))
		if len(n.Plaintext) != 64 {
			t.Fatalf("NumberOfBytes data key length %d", len(n.Plaintext))
		}
		_, err := c.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{KeyId: aws.String(keyID)})
		wantCode(t, err, "ValidationException")

		wp := must[*kms.GenerateDataKeyWithoutPlaintextOutput](t)(c.GenerateDataKeyWithoutPlaintext(ctx, &kms.GenerateDataKeyWithoutPlaintextInput{KeyId: aws.String(keyID), KeySpec: kmstypes.DataKeySpecAes128}))
		dec = must[*kms.DecryptOutput](t)(c.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: wp.CiphertextBlob}))
		if len(dec.Plaintext) != 16 {
			t.Fatalf("AES_128 data key length %d", len(dec.Plaintext))
		}

		re := must[*kms.ReEncryptOutput](t)(c.ReEncrypt(ctx, &kms.ReEncryptInput{
			CiphertextBlob: dk.CiphertextBlob, SourceEncryptionContext: ec,
			DestinationKeyId: aws.String("harness-default-key"), DestinationEncryptionContext: map[string]string{"moved": "yes"},
		}))
		if aws.ToString(re.SourceKeyId) != keyARN {
			t.Fatalf("ReEncrypt SourceKeyId %s", aws.ToString(re.SourceKeyId))
		}
		dec = must[*kms.DecryptOutput](t)(c.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: re.CiphertextBlob, EncryptionContext: map[string]string{"moved": "yes"}}))
		if !bytes.Equal(dec.Plaintext, dk.Plaintext) {
			t.Fatal("re-encrypted data key differs")
		}
	})

	t.Run("GenerateDataKeyPair FIPS specs only", func(t *testing.T) {
		pair := must[*kms.GenerateDataKeyPairOutput](t)(c.GenerateDataKeyPair(ctx, &kms.GenerateDataKeyPairInput{KeyId: aws.String(keyID), KeyPairSpec: kmstypes.DataKeyPairSpecEccNistP256}))
		pub, err := x509.ParsePKIXPublicKey(pair.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		dec := must[*kms.DecryptOutput](t)(c.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: pair.PrivateKeyCiphertextBlob}))
		if !bytes.Equal(dec.Plaintext, pair.PrivateKeyPlaintext) {
			t.Fatal("private key ciphertext does not decrypt to the plaintext")
		}
		priv, err := x509.ParsePKCS8PrivateKey(pair.PrivateKeyPlaintext)
		if err != nil {
			t.Fatal(err)
		}
		if !priv.(*ecdsa.PrivateKey).PublicKey.Equal(pub) {
			t.Fatal("key pair halves do not match")
		}
		np := must[*kms.GenerateDataKeyPairWithoutPlaintextOutput](t)(c.GenerateDataKeyPairWithoutPlaintext(ctx, &kms.GenerateDataKeyPairWithoutPlaintextInput{KeyId: aws.String(keyID), KeyPairSpec: kmstypes.DataKeyPairSpecRsa2048}))
		if len(np.PublicKey) == 0 || len(np.PrivateKeyCiphertextBlob) == 0 {
			t.Fatal("GenerateDataKeyPairWithoutPlaintext returned nothing")
		}
		_, err = c.GenerateDataKeyPair(ctx, &kms.GenerateDataKeyPairInput{KeyId: aws.String(keyID), KeyPairSpec: kmstypes.DataKeyPairSpecEccSecgP256k1})
		wantCode(t, err, "ValidationException")
	})

	t.Run("ListKeys pagination", func(t *testing.T) {
		for i := 0; i < 4; i++ {
			must[*kms.CreateKeyOutput](t)(c.CreateKey(ctx, &kms.CreateKeyInput{}))
		}
		seen := map[string]bool{}
		pages := 0
		p := kms.NewListKeysPaginator(c, &kms.ListKeysInput{Limit: aws.Int32(2)})
		for p.HasMorePages() {
			page := must[*kms.ListKeysOutput](t)(p.NextPage(ctx))
			pages++
			for _, k := range page.Keys {
				if seen[aws.ToString(k.KeyId)] {
					t.Fatalf("key %s listed twice", aws.ToString(k.KeyId))
				}
				seen[aws.ToString(k.KeyId)] = true
			}
		}
		if len(seen) < 6 || pages < 3 {
			t.Fatalf("listed %d keys over %d pages", len(seen), pages)
		}
		_, err := c.ListKeys(ctx, &kms.ListKeysInput{Marker: aws.String("forged")})
		wantCode(t, err, "ValidationException")
	})

	t.Run("aliases", func(t *testing.T) {
		for _, n := range []string{"alias/a1", "alias/a2", "alias/a3"} {
			must[*kms.CreateAliasOutput](t)(c.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String(n), TargetKeyId: aws.String(keyARN)}))
		}
		_, err := c.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String("alias/a1"), TargetKeyId: aws.String(keyID)})
		wantCode(t, err, "AlreadyExistsException")
		_, err = c.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String("alias/aws/s3"), TargetKeyId: aws.String(keyID)})
		wantCode(t, err, "NotAuthorizedException")

		var names []string
		p := kms.NewListAliasesPaginator(c, &kms.ListAliasesInput{Limit: aws.Int32(1)})
		for p.HasMorePages() {
			for _, a := range must[*kms.ListAliasesOutput](t)(p.NextPage(ctx)).Aliases {
				names = append(names, aws.ToString(a.AliasName))
				if !strings.HasPrefix(aws.ToString(a.AliasArn), "arn:aws:kms:") {
					t.Fatalf("alias ARN %q", aws.ToString(a.AliasArn))
				}
			}
		}
		if !sort.StringsAreSorted(names) || len(names) != 4 {
			t.Fatalf("ListAliases = %v", names)
		}

		must[*kms.UpdateAliasOutput](t)(c.UpdateAlias(ctx, &kms.UpdateAliasInput{AliasName: aws.String("alias/a3"), TargetKeyId: aws.String("harness-default-key")}))
		byKey := must[*kms.ListAliasesOutput](t)(c.ListAliases(ctx, &kms.ListAliasesInput{KeyId: aws.String("harness-default-key")}))
		if len(byKey.Aliases) != 1 || aws.ToString(byKey.Aliases[0].AliasName) != "alias/a3" {
			t.Fatalf("ListAliases by key = %+v", byKey.Aliases)
		}
		must[*kms.DeleteAliasOutput](t)(c.DeleteAlias(ctx, &kms.DeleteAliasInput{AliasName: aws.String("alias/a3")}))
		_, err = c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String("alias/a3")})
		wantCode(t, err, "NotFoundException")
		_, err = c.UpdateAlias(ctx, &kms.UpdateAliasInput{AliasName: aws.String("alias/missing"), TargetKeyId: aws.String(keyID)})
		wantCode(t, err, "NotFoundException")
	})

	t.Run("Enable, Disable, Schedule and Cancel deletion", func(t *testing.T) {
		k := must[*kms.CreateKeyOutput](t)(c.CreateKey(ctx, &kms.CreateKeyInput{})).KeyMetadata.KeyId
		must[*kms.DisableKeyOutput](t)(c.DisableKey(ctx, &kms.DisableKeyInput{KeyId: k}))
		_, err := c.Encrypt(ctx, &kms.EncryptInput{KeyId: k, Plaintext: []byte("x")})
		wantCode(t, err, "DisabledException")
		must[*kms.EnableKeyOutput](t)(c.EnableKey(ctx, &kms.EnableKeyInput{KeyId: k}))
		must[*kms.EncryptOutput](t)(c.Encrypt(ctx, &kms.EncryptInput{KeyId: k, Plaintext: []byte("x")}))

		sched := must[*kms.ScheduleKeyDeletionOutput](t)(c.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: k, PendingWindowInDays: aws.Int32(7)}))
		if sched.DeletionDate == nil || time.Until(*sched.DeletionDate) < 6*24*time.Hour || sched.KeyState != kmstypes.KeyStatePendingDeletion {
			t.Fatalf("ScheduleKeyDeletion = %+v", sched)
		}
		desc := must[*kms.DescribeKeyOutput](t)(c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: k}))
		if desc.KeyMetadata.KeyState != kmstypes.KeyStatePendingDeletion || desc.KeyMetadata.DeletionDate == nil {
			t.Fatalf("pending key metadata = %+v", desc.KeyMetadata)
		}
		_, err = c.Encrypt(ctx, &kms.EncryptInput{KeyId: k, Plaintext: []byte("x")})
		wantCode(t, err, "KMSInvalidStateException")
		_, err = c.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: k})
		wantCode(t, err, "KMSInvalidStateException")

		must[*kms.CancelKeyDeletionOutput](t)(c.CancelKeyDeletion(ctx, &kms.CancelKeyDeletionInput{KeyId: k}))
		desc = must[*kms.DescribeKeyOutput](t)(c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: k}))
		if desc.KeyMetadata.KeyState != kmstypes.KeyStateDisabled {
			t.Fatalf("cancelled key state = %s, want Disabled", desc.KeyMetadata.KeyState)
		}
		_, err = c.CancelKeyDeletion(ctx, &kms.CancelKeyDeletionInput{KeyId: k})
		wantCode(t, err, "KMSInvalidStateException")
		_, err = c.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: k, PendingWindowInDays: aws.Int32(3)})
		wantCode(t, err, "ValidationException")
	})

	t.Run("Get and Put key policy", func(t *testing.T) {
		k := must[*kms.CreateKeyOutput](t)(c.CreateKey(ctx, &kms.CreateKeyInput{})).KeyMetadata.KeyId
		def := must[*kms.GetKeyPolicyOutput](t)(c.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{KeyId: k}))
		if !strings.Contains(aws.ToString(def.Policy), "kms:*") {
			t.Fatalf("default policy = %s", aws.ToString(def.Policy))
		}
		deny := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"kms:*","Resource":"*"},{"Effect":"Deny","Principal":"*","Action":"kms:Encrypt","Resource":"*"}]}`
		must[*kms.PutKeyPolicyOutput](t)(c.PutKeyPolicy(ctx, &kms.PutKeyPolicyInput{KeyId: k, Policy: aws.String(deny), PolicyName: aws.String("default")}))
		got := must[*kms.GetKeyPolicyOutput](t)(c.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{KeyId: k, PolicyName: aws.String("default")}))
		if !strings.Contains(aws.ToString(got.Policy), "Deny") {
			t.Fatalf("policy not stored: %s", aws.ToString(got.Policy))
		}
		_, err := c.Encrypt(ctx, &kms.EncryptInput{KeyId: k, Plaintext: []byte("x")})
		wantCode(t, err, "AccessDeniedException")
		_, err = c.PutKeyPolicy(ctx, &kms.PutKeyPolicyInput{KeyId: k, Policy: aws.String("{nope")})
		wantCode(t, err, "MalformedPolicyDocumentException")
	})

	t.Run("Sign, Verify and GetPublicKey", func(t *testing.T) {
		msg := []byte("signed by citadel")
		digest := sha256.Sum256(msg)

		ec := must[*kms.CreateKeyOutput](t)(c.CreateKey(ctx, &kms.CreateKeyInput{KeyUsage: kmstypes.KeyUsageTypeSignVerify, KeySpec: kmstypes.KeySpecEccNistP256})).KeyMetadata.KeyId
		sig := must[*kms.SignOutput](t)(c.Sign(ctx, &kms.SignInput{KeyId: ec, Message: msg, MessageType: kmstypes.MessageTypeRaw, SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256}))
		must[*kms.VerifyOutput](t)(c.Verify(ctx, &kms.VerifyInput{KeyId: ec, Message: msg, Signature: sig.Signature, SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256}))
		pk := must[*kms.GetPublicKeyOutput](t)(c.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: ec}))
		pub, err := x509.ParsePKIXPublicKey(pk.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), digest[:], sig.Signature) {
			t.Fatal("ECDSA signature does not verify with the published public key")
		}
		_, err = c.Verify(ctx, &kms.VerifyInput{KeyId: ec, Message: []byte("tampered"), Signature: sig.Signature, SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256})
		wantCode(t, err, "KMSInvalidSignatureException")
		_, err = c.Encrypt(ctx, &kms.EncryptInput{KeyId: ec, Plaintext: []byte("x")})
		wantCode(t, err, "InvalidKeyUsageException")

		rk := must[*kms.CreateKeyOutput](t)(c.CreateKey(ctx, &kms.CreateKeyInput{KeyUsage: kmstypes.KeyUsageTypeSignVerify, KeySpec: kmstypes.KeySpecRsa2048})).KeyMetadata.KeyId
		pss := must[*kms.SignOutput](t)(c.Sign(ctx, &kms.SignInput{KeyId: rk, Message: digest[:], MessageType: kmstypes.MessageTypeDigest, SigningAlgorithm: kmstypes.SigningAlgorithmSpecRsassaPssSha256}))
		rpk := must[*kms.GetPublicKeyOutput](t)(c.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: rk}))
		rpub, err := x509.ParsePKIXPublicKey(rpk.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := rsa.VerifyPSS(rpub.(*rsa.PublicKey), crypto.SHA256, digest[:], pss.Signature, nil); err != nil {
			t.Fatalf("RSASSA-PSS signature does not verify: %v", err)
		}
		if len(rpk.SigningAlgorithms) != 6 {
			t.Fatalf("RSA signing algorithms = %v", rpk.SigningAlgorithms)
		}
	})
}
