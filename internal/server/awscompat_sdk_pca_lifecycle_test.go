package server

import (
	"context"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/acmpca/schemas"
	pcatypes "github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	"github.com/aws/smithy-go/transport/http/protocol/awsjson"

	"github.com/worlddrknss/citadel/internal/config"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/memory"
)

// newPCAClient is the SDK harness for ACM PCA: the memory store with KMS
// signing keys (keyStore), so CAs can be created.
func newPCAClient(t *testing.T) *acmpca.Client {
	t.Helper()
	defaultKey := sampleKey(7)
	defaultKey.ID = "harness-default-key"
	mem := &memory.Store{DefaultKey: defaultKey, Region: harnessRegion, AccountID: harnessAccount}
	st := &keyStore{Store: mem, keys: map[string]store.KMSKey{}}
	s := &Server{cfg: config.Config{ExpectedAccessKey: harnessAccessKey, SecretAccessKey: harnessSecret}, store: st}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	cfg := aws.Config{
		Region:      harnessRegion,
		Credentials: credentials.NewStaticCredentialsProvider(harnessAccessKey, harnessSecret, ""),
		HTTPClient:  srv.Client(),
		Retryer:     func() aws.Retryer { return aws.NopRetryer{} },
	}
	// acmpca prefers Smithy RPCv2 CBOR; Citadel serves AWS JSON 1.1.
	return acmpca.NewFromConfig(cfg, func(o *acmpca.Options) {
		o.EndpointResolverV2 = fixedEndpoint[acmpca.EndpointParameters]{*u}
		o.Protocol = awsjson.New11(schemas.ACMPrivateCA)
	})
}

func TestSDKPCADeleteRestore(t *testing.T) {
	c := newPCAClient(t)
	ctx := context.Background()
	created := must[*acmpca.CreateCertificateAuthorityOutput](t)(c.CreateCertificateAuthority(ctx, &acmpca.CreateCertificateAuthorityInput{
		CertificateAuthorityType: pcatypes.CertificateAuthorityTypeRoot,
		CertificateAuthorityConfiguration: &pcatypes.CertificateAuthorityConfiguration{
			KeyAlgorithm:     pcatypes.KeyAlgorithmEcPrime256v1,
			SigningAlgorithm: pcatypes.SigningAlgorithmSha256withecdsa,
			Subject:          &pcatypes.ASN1Subject{CommonName: aws.String("SDK Lifecycle Root")},
		},
	}))
	arn := created.CertificateAuthorityArn
	describe := func() *pcatypes.CertificateAuthority {
		t.Helper()
		out := must[*acmpca.DescribeCertificateAuthorityOutput](t)(c.DescribeCertificateAuthority(ctx, &acmpca.DescribeCertificateAuthorityInput{CertificateAuthorityArn: arn}))
		return out.CertificateAuthority
	}

	_, err := c.DeleteCertificateAuthority(ctx, &acmpca.DeleteCertificateAuthorityInput{CertificateAuthorityArn: arn})
	wantCode(t, err, "InvalidStateException")

	must[*acmpca.UpdateCertificateAuthorityOutput](t)(c.UpdateCertificateAuthority(ctx, &acmpca.UpdateCertificateAuthorityInput{
		CertificateAuthorityArn: arn, Status: pcatypes.CertificateAuthorityStatusDisabled,
	}))
	if ca := describe(); ca.Status != pcatypes.CertificateAuthorityStatusDisabled {
		t.Fatalf("status after disable = %s", ca.Status)
	}

	must[*acmpca.DeleteCertificateAuthorityOutput](t)(c.DeleteCertificateAuthority(ctx, &acmpca.DeleteCertificateAuthorityInput{
		CertificateAuthorityArn: arn, PermanentDeletionTimeInDays: aws.Int32(7),
	}))
	ca := describe()
	if ca.Status != pcatypes.CertificateAuthorityStatusDeleted || ca.RestorableUntil == nil {
		t.Fatalf("after delete = %s %v", ca.Status, ca.RestorableUntil)
	}

	must[*acmpca.RestoreCertificateAuthorityOutput](t)(c.RestoreCertificateAuthority(ctx, &acmpca.RestoreCertificateAuthorityInput{CertificateAuthorityArn: arn}))
	if ca := describe(); ca.Status != pcatypes.CertificateAuthorityStatusDisabled || ca.RestorableUntil != nil {
		t.Fatalf("after restore = %s %v", ca.Status, ca.RestorableUntil)
	}
	_, err = c.RestoreCertificateAuthority(ctx, &acmpca.RestoreCertificateAuthorityInput{CertificateAuthorityArn: arn})
	wantCode(t, err, "InvalidStateException")

	must[*acmpca.UpdateCertificateAuthorityOutput](t)(c.UpdateCertificateAuthority(ctx, &acmpca.UpdateCertificateAuthorityInput{
		CertificateAuthorityArn: arn, Status: pcatypes.CertificateAuthorityStatusActive,
	}))
	if ca := describe(); ca.Status != pcatypes.CertificateAuthorityStatusActive {
		t.Fatalf("status after enable = %s", ca.Status)
	}
	_, err = c.DeleteCertificateAuthority(ctx, &acmpca.DeleteCertificateAuthorityInput{CertificateAuthorityArn: aws.String("arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/nope")})
	wantCode(t, err, "ResourceNotFoundException")
}
