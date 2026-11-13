package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	pcaschemas "github.com/aws/aws-sdk-go-v2/service/acmpca/schemas"
	pcatypes "github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/smithy-go/transport/http/protocol/awsjson"
)

// pkiClients builds ACM and ACM PCA clients against the harness server.
func (h *sdkHarness) pkiClients() (*acm.Client, *acmpca.Client) {
	u, _ := url.Parse(h.srv.URL)
	cfg := aws.Config{
		Region:      harnessRegion,
		Credentials: h.creds,
		HTTPClient:  h.srv.Client(),
		Retryer:     func() aws.Retryer { return aws.NopRetryer{} },
	}
	return acm.NewFromConfig(cfg, func(o *acm.Options) { o.EndpointResolverV2 = fixedEndpoint[acm.EndpointParameters]{*u} }),
		acmpca.NewFromConfig(cfg, func(o *acmpca.Options) {
			o.EndpointResolverV2 = fixedEndpoint[acmpca.EndpointParameters]{*u}
			// aws-sdk-go-v2 acmpca defaults to Smithy RPCv2 CBOR, which Citadel
			// does not speak; select the AWS JSON 1.1 protocol ACM PCA also serves.
			o.Protocol = awsjson.New11(pcaschemas.ACMPrivateCA)
		})
}

func TestSDKSecretsManagerParity(t *testing.T) {
	h := newSDKHarness(t)
	ctx := context.Background()
	c := h.sm
	for _, name := range []string{"parity/b", "parity/a", "parity/d", "parity/c"} {
		must[*secretsmanager.CreateSecretOutput](t)(c.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: aws.String(name), SecretString: aws.String("v")}))
	}

	t.Run("DeleteResourcePolicy", func(t *testing.T) {
		policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"secretsmanager:*","Resource":"*"},{"Sid":"x","Effect":"Allow","Principal":"*","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`
		must[*secretsmanager.PutResourcePolicyOutput](t)(c.PutResourcePolicy(ctx, &secretsmanager.PutResourcePolicyInput{SecretId: aws.String("parity/a"), ResourcePolicy: aws.String(policy)}))
		got := must[*secretsmanager.GetResourcePolicyOutput](t)(c.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{SecretId: aws.String("parity/a")}))
		if aws.ToString(got.ResourcePolicy) == "" || !strings.Contains(aws.ToString(got.ResourcePolicy), `"x"`) {
			t.Fatalf("policy before delete = %s", aws.ToString(got.ResourcePolicy))
		}
		del := must[*secretsmanager.DeleteResourcePolicyOutput](t)(c.DeleteResourcePolicy(ctx, &secretsmanager.DeleteResourcePolicyInput{SecretId: aws.String("parity/a")}))
		wantRequestID(t, del.ResultMetadata)
		if aws.ToString(del.Name) != "parity/a" || aws.ToString(del.ARN) == "" {
			t.Fatalf("DeleteResourcePolicy = %+v", del)
		}
		got = must[*secretsmanager.GetResourcePolicyOutput](t)(c.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{SecretId: aws.String("parity/a")}))
		if strings.Contains(aws.ToString(got.ResourcePolicy), `"x"`) {
			t.Fatalf("policy survived delete: %s", aws.ToString(got.ResourcePolicy))
		}
		// The secret is still readable under the default policy.
		must[*secretsmanager.GetSecretValueOutput](t)(c.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String("parity/a")}))
		_, err := c.DeleteResourcePolicy(ctx, &secretsmanager.DeleteResourcePolicyInput{SecretId: aws.String("parity/missing")})
		wantCode(t, err, "ResourceNotFoundException")
	})

	t.Run("ListSecrets SortOrder", func(t *testing.T) {
		list := func(order smtypes.SortOrderType) []string {
			var names []string
			p := secretsmanager.NewListSecretsPaginator(c, &secretsmanager.ListSecretsInput{SortOrder: order, MaxResults: aws.Int32(3)})
			for p.HasMorePages() {
				page := must[*secretsmanager.ListSecretsOutput](t)(p.NextPage(ctx))
				for _, s := range page.SecretList {
					names = append(names, aws.ToString(s.Name))
				}
			}
			return names
		}
		asc, desc := list(smtypes.SortOrderTypeAsc), list(smtypes.SortOrderTypeDesc)
		want := []string{"parity/a", "parity/b", "parity/c", "parity/d"}
		if !slices.Equal(asc, want) {
			t.Fatalf("asc = %v", asc)
		}
		if !slices.Equal(desc, []string{"parity/d", "parity/c", "parity/b", "parity/a"}) {
			t.Fatalf("desc = %v", desc)
		}
		if def := list(""); !slices.Equal(def, want) {
			t.Fatalf("default order = %v", def)
		}
		_, err := c.ListSecrets(ctx, &secretsmanager.ListSecretsInput{SortOrder: "sideways"})
		wantCode(t, err, "InvalidParameterException")
		_, err = c.ListSecrets(ctx, &secretsmanager.ListSecretsInput{SortBy: smtypes.SortByTypeCreatedDate})
		wantCode(t, err, "InvalidParameterException")
		// A token from one order is not valid for the other.
		page := must[*secretsmanager.ListSecretsOutput](t)(c.ListSecrets(ctx, &secretsmanager.ListSecretsInput{SortOrder: smtypes.SortOrderTypeDesc, MaxResults: aws.Int32(1)}))
		_, err = c.ListSecrets(ctx, &secretsmanager.ListSecretsInput{SortOrder: smtypes.SortOrderTypeAsc, NextToken: page.NextToken})
		wantCode(t, err, "InvalidNextTokenException")
	})
}

func TestSDKSSMUnlabelParameterVersion(t *testing.T) {
	h := newSDKHarness(t)
	ctx := context.Background()
	c := h.ssm
	must[*ssm.PutParameterOutput](t)(c.PutParameter(ctx, &ssm.PutParameterInput{Name: aws.String("/parity/url"), Value: aws.String("v1"), Type: ssmtypes.ParameterTypeString}))
	must[*ssm.LabelParameterVersionOutput](t)(c.LabelParameterVersion(ctx, &ssm.LabelParameterVersionInput{
		Name: aws.String("/parity/url"), ParameterVersion: aws.Int64(1), Labels: []string{"stable", "blue"},
	}))
	out := must[*ssm.UnlabelParameterVersionOutput](t)(c.UnlabelParameterVersion(ctx, &ssm.UnlabelParameterVersionInput{
		Name: aws.String("/parity/url"), ParameterVersion: aws.Int64(1), Labels: []string{"stable", "missing"},
	}))
	wantRequestID(t, out.ResultMetadata)
	if !slices.Equal(out.RemovedLabels, []string{"stable"}) || !slices.Equal(out.InvalidLabels, []string{"missing"}) {
		t.Fatalf("UnlabelParameterVersion = removed %v invalid %v", out.RemovedLabels, out.InvalidLabels)
	}
	hist := must[*ssm.GetParameterHistoryOutput](t)(c.GetParameterHistory(ctx, &ssm.GetParameterHistoryInput{Name: aws.String("/parity/url")}))
	if len(hist.Parameters) != 1 || !slices.Equal(hist.Parameters[0].Labels, []string{"blue"}) {
		t.Fatalf("labels after unlabel = %+v", hist.Parameters)
	}
	_, err := c.UnlabelParameterVersion(ctx, &ssm.UnlabelParameterVersionInput{Name: aws.String("/parity/url"), ParameterVersion: aws.Int64(9), Labels: []string{"blue"}})
	wantCode(t, err, "ParameterVersionNotFound")
	_, err = c.UnlabelParameterVersion(ctx, &ssm.UnlabelParameterVersionInput{Name: aws.String("/parity/none"), ParameterVersion: aws.Int64(1), Labels: []string{"blue"}})
	wantCode(t, err, "ParameterNotFound")
}

// createRootCA creates an ACTIVE root CA through the SDK.
func createRootCA(t *testing.T, ctx context.Context, pca *acmpca.Client, cn string) string {
	t.Helper()
	out := must[*acmpca.CreateCertificateAuthorityOutput](t)(pca.CreateCertificateAuthority(ctx, &acmpca.CreateCertificateAuthorityInput{
		CertificateAuthorityType: pcatypes.CertificateAuthorityTypeRoot,
		CertificateAuthorityConfiguration: &pcatypes.CertificateAuthorityConfiguration{
			KeyAlgorithm: pcatypes.KeyAlgorithmEcPrime256v1, SigningAlgorithm: pcatypes.SigningAlgorithmSha256withecdsa,
			Subject: &pcatypes.ASN1Subject{CommonName: aws.String(cn)},
		},
	}))
	return aws.ToString(out.CertificateAuthorityArn)
}

func TestSDKACMIdempotencyToken(t *testing.T) {
	h := newSDKHarness(t)
	ctx := context.Background()
	acmc, pca := h.pkiClients()
	caARN := createRootCA(t, ctx, pca, "Idempotency Root")

	req := func(domain, token string) (*acm.RequestCertificateOutput, error) {
		return acmc.RequestCertificate(ctx, &acm.RequestCertificateInput{
			DomainName: aws.String(domain), CertificateAuthorityArn: aws.String(caARN), IdempotencyToken: aws.String(token),
		})
	}
	first := must[*acm.RequestCertificateOutput](t)(req("app.example.com", "tok_1"))
	second := must[*acm.RequestCertificateOutput](t)(req("app.example.com", "tok_1"))
	if aws.ToString(first.CertificateArn) == "" || aws.ToString(first.CertificateArn) != aws.ToString(second.CertificateArn) {
		t.Fatalf("same token gave %s and %s", aws.ToString(first.CertificateArn), aws.ToString(second.CertificateArn))
	}
	other := must[*acm.RequestCertificateOutput](t)(req("app.example.com", "tok_2"))
	if aws.ToString(other.CertificateArn) == aws.ToString(first.CertificateArn) {
		t.Fatal("a different token returned the same certificate")
	}
	_, err := req("other.example.com", "tok_1")
	wantCode(t, err, "InvalidParameterException")
	_, err = req("app.example.com", "not a token!")
	wantCode(t, err, "ValidationException")
	list := must[*acm.ListCertificatesOutput](t)(acmc.ListCertificates(ctx, &acm.ListCertificatesInput{}))
	if len(list.CertificateSummaryList) != 2 {
		t.Fatalf("certificates issued = %d, want 2", len(list.CertificateSummaryList))
	}

	// ImportCertificate (its IdempotencyToken is a Citadel extension the
	// SDK cannot send; see TestACMImportIdempotencyToken).
	certPEM, keyPEM := selfSignedPEM(t, "imported.example.com")
	imp := must[*acm.ImportCertificateOutput](t)(acmc.ImportCertificate(ctx, &acm.ImportCertificateInput{Certificate: certPEM, PrivateKey: keyPEM}))
	if aws.ToString(imp.CertificateArn) == "" {
		t.Fatal("ImportCertificate returned no ARN")
	}
}

func TestSDKACMPCASubordinateCA(t *testing.T) {
	h := newSDKHarness(t)
	ctx := context.Background()
	_, pca := h.pkiClients()
	rootARN := createRootCA(t, ctx, pca, "Parity Root")

	sub := must[*acmpca.CreateCertificateAuthorityOutput](t)(pca.CreateCertificateAuthority(ctx, &acmpca.CreateCertificateAuthorityInput{
		CertificateAuthorityType: pcatypes.CertificateAuthorityTypeSubordinate,
		CertificateAuthorityConfiguration: &pcatypes.CertificateAuthorityConfiguration{
			KeyAlgorithm: pcatypes.KeyAlgorithmEcPrime256v1, SigningAlgorithm: pcatypes.SigningAlgorithmSha256withecdsa,
			Subject: &pcatypes.ASN1Subject{CommonName: aws.String("Parity Issuing CA"), Organization: aws.String("Citadel")},
		},
	}))
	subARN := sub.CertificateAuthorityArn
	desc := must[*acmpca.DescribeCertificateAuthorityOutput](t)(pca.DescribeCertificateAuthority(ctx, &acmpca.DescribeCertificateAuthorityInput{CertificateAuthorityArn: subARN}))
	if desc.CertificateAuthority.Status != pcatypes.CertificateAuthorityStatusPendingCertificate || desc.CertificateAuthority.Type != pcatypes.CertificateAuthorityTypeSubordinate {
		t.Fatalf("new subordinate CA = %s %s", desc.CertificateAuthority.Status, desc.CertificateAuthority.Type)
	}
	_, err := pca.GetCertificateAuthorityCertificate(ctx, &acmpca.GetCertificateAuthorityCertificateInput{CertificateAuthorityArn: subARN})
	wantCode(t, err, "InvalidStateException")

	csrOut := must[*acmpca.GetCertificateAuthorityCsrOutput](t)(pca.GetCertificateAuthorityCsr(ctx, &acmpca.GetCertificateAuthorityCsrInput{CertificateAuthorityArn: subARN}))
	block, _ := pem.Decode([]byte(aws.ToString(csrOut.Csr)))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("Csr = %q", aws.ToString(csrOut.Csr))
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != "Parity Issuing CA" {
		t.Fatalf("CSR = %+v, %v", csr, err)
	}

	issued := must[*acmpca.IssueCertificateOutput](t)(pca.IssueCertificate(ctx, &acmpca.IssueCertificateInput{
		CertificateAuthorityArn: aws.String(rootARN), Csr: []byte(aws.ToString(csrOut.Csr)),
		SigningAlgorithm: pcatypes.SigningAlgorithmSha256withecdsa,
		TemplateArn:      aws.String("arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1"),
		Validity:         &pcatypes.Validity{Type: pcatypes.ValidityPeriodTypeYears, Value: aws.Int64(3)},
	}))
	got := must[*acmpca.GetCertificateOutput](t)(pca.GetCertificate(ctx, &acmpca.GetCertificateInput{CertificateAuthorityArn: aws.String(rootARN), CertificateArn: issued.CertificateArn}))
	subCert := parsePEMChain(t, aws.ToString(got.Certificate))[0]
	if !subCert.IsCA || subCert.MaxPathLen != 0 || !subCert.MaxPathLenZero {
		t.Fatalf("issued subordinate certificate: IsCA=%v MaxPathLen=%d", subCert.IsCA, subCert.MaxPathLen)
	}

	// A certificate for another key is refused.
	otherPEM, _ := selfSignedPEM(t, "Other CA")
	_, err = pca.ImportCertificateAuthorityCertificate(ctx, &acmpca.ImportCertificateAuthorityCertificateInput{
		CertificateAuthorityArn: subARN, Certificate: otherPEM, CertificateChain: []byte(aws.ToString(got.CertificateChain)),
	})
	wantCode(t, err, "ValidationException")

	imp := must[*acmpca.ImportCertificateAuthorityCertificateOutput](t)(pca.ImportCertificateAuthorityCertificate(ctx, &acmpca.ImportCertificateAuthorityCertificateInput{
		CertificateAuthorityArn: subARN, Certificate: []byte(aws.ToString(got.Certificate)), CertificateChain: []byte(aws.ToString(got.CertificateChain)),
	}))
	wantRequestID(t, imp.ResultMetadata)
	desc = must[*acmpca.DescribeCertificateAuthorityOutput](t)(pca.DescribeCertificateAuthority(ctx, &acmpca.DescribeCertificateAuthorityInput{CertificateAuthorityArn: subARN}))
	if desc.CertificateAuthority.Status != pcatypes.CertificateAuthorityStatusActive {
		t.Fatalf("after import status = %s", desc.CertificateAuthority.Status)
	}
	_, err = pca.ImportCertificateAuthorityCertificate(ctx, &acmpca.ImportCertificateAuthorityCertificateInput{
		CertificateAuthorityArn: subARN, Certificate: []byte(aws.ToString(got.Certificate)), CertificateChain: []byte(aws.ToString(got.CertificateChain)),
	})
	wantCode(t, err, "InvalidStateException")

	// The activated CA issues leaves that chain through it to the root.
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafCSR, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "svc.example.com"}, DNSNames: []string{"svc.example.com"}}, leafKey)
	leafOut := must[*acmpca.IssueCertificateOutput](t)(pca.IssueCertificate(ctx, &acmpca.IssueCertificateInput{
		CertificateAuthorityArn: subARN, Csr: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: leafCSR}),
		SigningAlgorithm: pcatypes.SigningAlgorithmSha256withecdsa,
		Validity:         &pcatypes.Validity{Type: pcatypes.ValidityPeriodTypeDays, Value: aws.Int64(30)},
	}))
	leafGot := must[*acmpca.GetCertificateOutput](t)(pca.GetCertificate(ctx, &acmpca.GetCertificateInput{CertificateAuthorityArn: subARN, CertificateArn: leafOut.CertificateArn}))
	chain := parsePEMChain(t, aws.ToString(leafGot.CertificateChain))
	if len(chain) != 2 {
		t.Fatalf("leaf chain has %d certificates, want 2 (issuing CA and root)", len(chain))
	}
	verifyChain(t, parsePEMChain(t, aws.ToString(leafGot.Certificate))[0], chain, x509.ExtKeyUsageServerAuth)

	// PathLen0 below a PathLen0 CA is refused.
	_, err = pca.IssueCertificate(ctx, &acmpca.IssueCertificateInput{
		CertificateAuthorityArn: subARN, Csr: []byte(aws.ToString(csrOut.Csr)), SigningAlgorithm: pcatypes.SigningAlgorithmSha256withecdsa,
		TemplateArn: aws.String("arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1"),
		Validity:    &pcatypes.Validity{Type: pcatypes.ValidityPeriodTypeYears, Value: aws.Int64(1)},
	})
	wantCode(t, err, "InvalidStateException")
}

// selfSignedPEM returns a self-signed P-256 certificate and its key.
func selfSignedPEM(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{"imported.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// TestACMImportIdempotencyToken covers the Citadel ImportCertificate
// IdempotencyToken extension, which the SDK has no field for.
func TestACMImportIdempotencyToken(t *testing.T) {
	e := newPKIEnv(t, func(s *Server) { s.cfg.InsecureDev = true })
	certPEM, keyPEM := selfSignedPEM(t, "imported.example.com")
	body := map[string]any{"Certificate": certPEM, "PrivateKey": keyPEM, "IdempotencyToken": "imp_1"}
	first := mustAWS(t, e.h, "CertificateManager.ImportCertificate", body)
	second := mustAWS(t, e.h, "CertificateManager.ImportCertificate", body)
	if first["CertificateArn"] == nil || first["CertificateArn"] != second["CertificateArn"] {
		t.Fatalf("same token gave %v and %v", first["CertificateArn"], second["CertificateArn"])
	}
	otherPEM, otherKey := selfSignedPEM(t, "other.example.com")
	code, m := awsCall(t, e.h, "CertificateManager.ImportCertificate", map[string]any{"Certificate": otherPEM, "PrivateKey": otherKey, "IdempotencyToken": "imp_1"})
	if code != 400 || m["__type"] != "InvalidParameterException" {
		t.Fatalf("reuse with other parameters = %d %v", code, m)
	}
	list := mustAWS(t, e.h, "CertificateManager.ListCertificates", map[string]any{})
	if n := len(list["CertificateSummaryList"].([]any)); n != 1 {
		t.Fatalf("imported certificates = %d, want 1", n)
	}
	// A failed request releases its token.
	code, _ = awsCall(t, e.h, "CertificateManager.ImportCertificate", map[string]any{"Certificate": otherPEM, "PrivateKey": keyPEM, "IdempotencyToken": "imp_2"})
	if code != 400 {
		t.Fatalf("mismatched key import = %d", code)
	}
	mustAWS(t, e.h, "CertificateManager.ImportCertificate", map[string]any{"Certificate": otherPEM, "PrivateKey": otherKey, "IdempotencyToken": "imp_2"})
}
