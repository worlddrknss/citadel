package server

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// TestSDKKMSLifecycle drives rotation, tagging, grants, RSA encryption keys,
// DeleteAlias and GenerateRandom through the real aws-sdk-go-v2 KMS client.
func TestSDKKMSLifecycle(t *testing.T) {
	h := newSDKHarness(t)
	ctx := context.Background()
	c := h.kms
	keyID := aws.ToString(must[*kms.CreateKeyOutput](t)(c.CreateKey(ctx, &kms.CreateKeyInput{})).KeyMetadata.KeyId)

	enc := must[*kms.EncryptOutput](t)(c.Encrypt(ctx, &kms.EncryptInput{KeyId: aws.String(keyID), Plaintext: []byte("before")}))

	must[*kms.EnableKeyRotationOutput](t)(c.EnableKeyRotation(ctx, &kms.EnableKeyRotationInput{KeyId: aws.String(keyID), RotationPeriodInDays: aws.Int32(120)}))
	st := must[*kms.GetKeyRotationStatusOutput](t)(c.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: aws.String(keyID)}))
	if !st.KeyRotationEnabled || aws.ToInt32(st.RotationPeriodInDays) != 120 || st.NextRotationDate == nil || st.NextRotationDate.IsZero() {
		t.Fatalf("rotation status %+v", st)
	}
	must[*kms.RotateKeyOnDemandOutput](t)(c.RotateKeyOnDemand(ctx, &kms.RotateKeyOnDemandInput{KeyId: aws.String(keyID)}))
	rots := must[*kms.ListKeyRotationsOutput](t)(c.ListKeyRotations(ctx, &kms.ListKeyRotationsInput{KeyId: aws.String(keyID)}))
	if len(rots.Rotations) != 1 || rots.Rotations[0].RotationType != kmstypes.RotationTypeOnDemand || rots.Rotations[0].RotationDate == nil {
		t.Fatalf("rotations %+v", rots.Rotations)
	}
	dec := must[*kms.DecryptOutput](t)(c.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: enc.CiphertextBlob}))
	if string(dec.Plaintext) != "before" {
		t.Fatal("pre-rotation ciphertext no longer decrypts")
	}
	must[*kms.DisableKeyRotationOutput](t)(c.DisableKeyRotation(ctx, &kms.DisableKeyRotationInput{KeyId: aws.String(keyID)}))

	must[*kms.TagResourceOutput](t)(c.TagResource(ctx, &kms.TagResourceInput{KeyId: aws.String(keyID), Tags: []kmstypes.Tag{{TagKey: aws.String("team"), TagValue: aws.String("core")}}}))
	tags := must[*kms.ListResourceTagsOutput](t)(c.ListResourceTags(ctx, &kms.ListResourceTagsInput{KeyId: aws.String(keyID)}))
	if len(tags.Tags) != 1 || aws.ToString(tags.Tags[0].TagValue) != "core" {
		t.Fatalf("tags %+v", tags.Tags)
	}
	must[*kms.UntagResourceOutput](t)(c.UntagResource(ctx, &kms.UntagResourceInput{KeyId: aws.String(keyID), TagKeys: []string{"team"}}))
	_, err := c.TagResource(ctx, &kms.TagResourceInput{KeyId: aws.String(keyID), Tags: []kmstypes.Tag{{TagKey: aws.String("aws:x"), TagValue: aws.String("y")}}})
	wantCode(t, err, "TagException")

	g := must[*kms.CreateGrantOutput](t)(c.CreateGrant(ctx, &kms.CreateGrantInput{KeyId: aws.String(keyID), GranteePrincipal: aws.String("arn:aws:iam::" + harnessAccount + ":user/app"), Operations: []kmstypes.GrantOperation{kmstypes.GrantOperationEncrypt}}))
	grants := must[*kms.ListGrantsOutput](t)(c.ListGrants(ctx, &kms.ListGrantsInput{KeyId: aws.String(keyID)}))
	if len(grants.Grants) != 1 || grants.Grants[0].CreationDate == nil || grants.Grants[0].CreationDate.IsZero() {
		t.Fatalf("grants %+v", grants.Grants)
	}
	must[*kms.RevokeGrantOutput](t)(c.RevokeGrant(ctx, &kms.RevokeGrantInput{KeyId: aws.String(keyID), GrantId: g.GrantId}))

	rsa := must[*kms.CreateKeyOutput](t)(c.CreateKey(ctx, &kms.CreateKeyInput{KeyUsage: kmstypes.KeyUsageTypeEncryptDecrypt, KeySpec: kmstypes.KeySpecRsa2048}))
	renc := must[*kms.EncryptOutput](t)(c.Encrypt(ctx, &kms.EncryptInput{KeyId: rsa.KeyMetadata.KeyId, Plaintext: []byte("oaep"), EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecRsaesOaepSha256}))
	rdec := must[*kms.DecryptOutput](t)(c.Decrypt(ctx, &kms.DecryptInput{KeyId: rsa.KeyMetadata.KeyId, CiphertextBlob: renc.CiphertextBlob, EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecRsaesOaepSha256}))
	if string(rdec.Plaintext) != "oaep" || rdec.EncryptionAlgorithm != kmstypes.EncryptionAlgorithmSpecRsaesOaepSha256 {
		t.Fatalf("RSA decrypt %+v", rdec)
	}
	_, err = c.EnableKeyRotation(ctx, &kms.EnableKeyRotationInput{KeyId: rsa.KeyMetadata.KeyId})
	wantCode(t, err, "UnsupportedOperationException")

	r := must[*kms.GenerateRandomOutput](t)(c.GenerateRandom(ctx, &kms.GenerateRandomInput{NumberOfBytes: aws.Int32(48)}))
	if len(r.Plaintext) != 48 {
		t.Fatalf("GenerateRandom returned %d bytes", len(r.Plaintext))
	}
	_, err = c.GenerateRandom(ctx, &kms.GenerateRandomInput{NumberOfBytes: aws.Int32(2048)})
	wantCode(t, err, "ValidationException")

	must[*kms.CreateAliasOutput](t)(c.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String("alias/gone"), TargetKeyId: aws.String(keyID)}))
	must[*kms.DeleteAliasOutput](t)(c.DeleteAlias(ctx, &kms.DeleteAliasInput{AliasName: aws.String("alias/gone")}))
}
