package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// KMSLifecycle exercises store.KMSLifecycleStore (rotation, tags, grants,
// usage counts, scheduled deletion) and its tenant isolation. st must
// support CreateKey and ScheduleKeyDeletion.
func KMSLifecycle(t *testing.T, st store.Store) {
	t.Helper()
	bg := context.Background()
	ctxA := store.WithCallerAccount(bg, AccountA)
	ctxB := store.WithCallerAccount(bg, AccountB)

	key, err := st.CreateKey(ctxA, "rotating", store.KeyUsageEncryptDecrypt, store.KeySpecSymmetricDefault)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if key.Origin != "" && key.Origin != store.OriginAWSKMS {
		t.Fatalf("origin %q", key.Origin)
	}
	aad := []byte("ctx")
	before, err := key.EncryptBlob([]byte("before"), aad)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("rotation", func(t *testing.T) {
		if _, err := st.SetKeyRotation(ctxB, key.ID, true, 0); err == nil {
			t.Fatal("account B enabled rotation on account A's key")
		}
		if _, err := st.SetKeyRotation(ctxA, key.ID, true, 89); !errors.Is(err, store.ErrInvalidRotationPeriod) {
			t.Fatalf("period 89: %v", err)
		}
		k, err := st.SetKeyRotation(ctxA, key.ID, true, 0)
		if err != nil {
			t.Fatalf("enable: %v", err)
		}
		if !k.RotationEnabled || k.RotationPeriodDays != store.DefaultRotationPeriodDays || k.NextRotationAt == nil {
			t.Fatalf("after enable: %+v", k)
		}
		now := time.Now().UTC()
		if _, err := st.RotateKeyMaterial(ctxA, key.ID, store.RotationKindAutomatic, now); !errors.Is(err, store.ErrRotationNotDue) {
			t.Fatalf("early automatic rotation: %v", err)
		}
		due := k.NextRotationAt.Add(time.Second)
		refs, err := st.ListKeysDueForRotation(bg, due)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, r := range refs {
			if r.KeyID == key.ID {
				found = true
				if r.AccountID != AccountA {
					t.Fatalf("due key account %q", r.AccountID)
				}
			}
		}
		if !found {
			t.Fatalf("key not due at %v: %+v", due, refs)
		}
		auto, err := st.RotateKeyMaterial(ctxA, key.ID, store.RotationKindAutomatic, due)
		if err != nil {
			t.Fatalf("automatic rotation: %v", err)
		}
		if _, err := st.RotateKeyMaterial(ctxA, key.ID, store.RotationKindAutomatic, due); !errors.Is(err, store.ErrRotationNotDue) {
			t.Fatalf("second automatic rotation at the same instant: %v", err)
		}
		if _, err := st.RotateKeyMaterial(ctxB, key.ID, store.RotationKindOnDemand, due); err == nil {
			t.Fatal("account B rotated account A's key")
		}
		od, err := st.RotateKeyMaterial(ctxA, key.ID, store.RotationKindOnDemand, due.Add(time.Second))
		if err != nil {
			t.Fatalf("on-demand rotation: %v", err)
		}
		k, err = st.ResolveByID(ctxA, key.ID)
		if err != nil {
			t.Fatal(err)
		}
		if k.CurrentMaterialID != od.MaterialID || len(k.Materials) != 2 {
			t.Fatalf("current %q materials %d", k.CurrentMaterialID, len(k.Materials))
		}
		if k.NextRotationAt == nil || !k.NextRotationAt.After(due) {
			t.Fatalf("automatic rotation did not reschedule: %v", k.NextRotationAt)
		}
		if got, err := k.DecryptBlob(before, aad); err != nil || string(got) != "before" {
			t.Fatalf("pre-rotation blob after rotation: %q %v", got, err)
		}
		after, _ := k.EncryptBlob([]byte("after"), aad)
		if got, err := k.DecryptBlob(after, aad); err != nil || string(got) != "after" {
			t.Fatalf("post-rotation blob: %q %v", got, err)
		}
		hist, err := st.ListKeyRotations(ctxA, key.ID)
		if err != nil || len(hist) != 2 || hist[0].MaterialID != od.MaterialID || hist[1].MaterialID != auto.MaterialID {
			t.Fatalf("history %+v %v", hist, err)
		}
		if hist[0].Kind != store.RotationKindOnDemand || hist[1].Kind != store.RotationKindAutomatic {
			t.Fatalf("history kinds %+v", hist)
		}
		if h, err := st.ListKeyRotations(ctxB, key.ID); err == nil && len(h) > 0 {
			t.Fatalf("account B sees account A's rotations: %+v", h)
		}
		k, err = st.SetKeyRotation(ctxA, key.ID, false, 0)
		if err != nil || k.RotationEnabled {
			t.Fatalf("disable: %+v %v", k, err)
		}
	})

	t.Run("asymmetric rotation refused", func(t *testing.T) {
		rsaKey, err := st.CreateKey(ctxA, "rsa", store.KeyUsageEncryptDecrypt, store.KeySpecRSA2048)
		if err != nil {
			t.Fatalf("CreateKey RSA_2048 ENCRYPT_DECRYPT: %v", err)
		}
		if rsaKey.KeySpec != store.KeySpecRSA2048 || len(rsaKey.PublicKeyRaw) == 0 {
			t.Fatalf("rsa key %+v", rsaKey.KeySpec)
		}
		if _, err := st.SetKeyRotation(ctxA, rsaKey.ID, true, 0); !errors.Is(err, store.ErrRotationUnsupported) {
			t.Fatalf("rotation on RSA key: %v", err)
		}
		if _, err := st.RotateKeyMaterial(ctxA, rsaKey.ID, store.RotationKindOnDemand, time.Now()); !errors.Is(err, store.ErrRotationUnsupported) {
			t.Fatalf("on-demand on RSA key: %v", err)
		}
	})

	t.Run("tags", func(t *testing.T) {
		if err := st.TagKey(ctxA, key.ID, []store.KMSTag{{Key: "team", Value: "core"}, {Key: "env", Value: "prod"}}); err != nil {
			t.Fatal(err)
		}
		if err := st.TagKey(ctxA, key.ID, []store.KMSTag{{Key: "team", Value: "platform"}}); err != nil {
			t.Fatal(err)
		}
		tags, err := st.ListKeyTags(ctxA, key.ID)
		if err != nil || len(tags) != 2 || tags[0] != (store.KMSTag{Key: "env", Value: "prod"}) || tags[1] != (store.KMSTag{Key: "team", Value: "platform"}) {
			t.Fatalf("tags %+v %v", tags, err)
		}
		if err := st.TagKey(ctxB, key.ID, []store.KMSTag{{Key: "x", Value: "y"}}); err == nil {
			t.Fatal("account B tagged account A's key")
		}
		if tags, err := st.ListKeyTags(ctxB, key.ID); err == nil && len(tags) > 0 {
			t.Fatalf("account B reads account A's tags: %+v", tags)
		}
		if err := st.TagKey(ctxA, key.ID, []store.KMSTag{{Key: "aws:x"}}); !errors.Is(err, store.ErrInvalidTags) {
			t.Fatalf("reserved tag: %v", err)
		}
		if err := st.UntagKey(ctxA, key.ID, []string{"env"}); err != nil {
			t.Fatal(err)
		}
		if tags, _ := st.ListKeyTags(ctxA, key.ID); len(tags) != 1 {
			t.Fatalf("after untag %+v", tags)
		}
	})

	t.Run("grants and policies", func(t *testing.T) {
		g, err := st.CreateGrant(ctxA, store.CreateGrantRequest{KeyID: key.ID, GranteePrincipal: "arn:aws:iam::111111111111:user/app", Operations: []string{"Encrypt"}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.CreateGrant(ctxB, store.CreateGrantRequest{KeyID: key.ID, GranteePrincipal: "arn:aws:iam::222222222222:user/x", Operations: []string{"Decrypt"}}); err == nil {
			t.Fatal("account B created a grant on account A's key")
		}
		if gs, _ := st.ListGrants(ctxB, key.ID); len(gs) != 0 {
			t.Fatalf("account B lists account A's grants: %+v", gs)
		}
		if _, err := st.FindGrant(ctxB, g.GrantID, ""); err == nil {
			t.Fatal("account B found account A's grant")
		}
		if err := st.RetireGrant(ctxB, "", g.GrantToken); err == nil {
			t.Fatal("account B retired account A's grant")
		}
		if err := st.RevokeGrant(ctxB, key.ID, g.GrantID); err == nil {
			t.Fatal("account B revoked account A's grant")
		}
		if found, err := st.FindGrant(ctxA, "", g.GrantToken); err != nil || found.GrantID != g.GrantID {
			t.Fatalf("FindGrant by token: %+v %v", found, err)
		}
		if err := st.RevokeGrant(ctxA, key.ID, g.GrantID); err != nil {
			t.Fatal(err)
		}
		if err := st.PutKeyPolicy(ctxA, key.ID, "default", `{"Statement":[]}`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.GetKeyPolicy(ctxB, key.ID, "default"); err == nil {
			t.Fatal("account B read account A's key policy")
		}
		if err := st.PutKeyPolicy(ctxB, key.ID, "default", `{}`); err == nil {
			t.Fatal("account B replaced account A's key policy")
		}
	})

	t.Run("usage counts", func(t *testing.T) {
		if _, _, err := st.CreateSecret(ctxA, store.CreateSecretRequest{Name: "kms/usage/A", SecretString: "v", KMSKeyID: key.ID}); err != nil {
			t.Fatal(err)
		}
		used, err := st.CountKeyUsage(ctxA, key)
		if err != nil || used.Secrets != 1 {
			t.Fatalf("usage %+v %v", used, err)
		}
		if used, _ := st.CountKeyUsage(ctxB, key); used.Secrets != 0 {
			t.Fatalf("account B counts account A's secrets: %+v", used)
		}
		v, err := st.GetSecretValue(ctxA, "kms/usage/A", "", "")
		if err != nil || v.SecretString == nil || *v.SecretString != "v" {
			t.Fatalf("secret under rotated key: %+v %v", v, err)
		}
	})

	t.Run("scheduled deletion", func(t *testing.T) {
		doomed, err := st.CreateKey(ctxA, "doomed", store.KeyUsageEncryptDecrypt, store.KeySpecSymmetricDefault)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.TagKey(ctxA, doomed.ID, []store.KMSTag{{Key: "a", Value: "b"}}); err != nil {
			t.Fatal(err)
		}
		when, err := st.ScheduleKeyDeletion(ctxA, doomed.ID, 7)
		if err != nil {
			t.Fatal(err)
		}
		refs, err := st.ListKeysPendingDeletion(bg, when.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if !containsRef(refs, doomed.ID) {
			t.Fatalf("doomed key not pending: %+v", refs)
		}
		if refs, _ := st.ListKeysPendingDeletion(bg, time.Now()); containsRef(refs, doomed.ID) {
			t.Fatal("key listed before its deletion date")
		}
		if err := st.DestroyKey(ctxB, doomed.ID); err == nil {
			t.Fatal("account B destroyed account A's key")
		}
		if err := st.DestroyKey(ctxA, doomed.ID); err != nil {
			t.Fatalf("DestroyKey: %v", err)
		}
		if _, err := st.ResolveByID(ctxA, doomed.ID); err == nil {
			t.Fatal("destroyed key still resolves")
		}
		keys, _ := st.ListKeys(ctxA)
		for _, k := range keys {
			if k.ID == doomed.ID {
				t.Fatal("destroyed key still listed")
			}
		}
		if refs, _ := st.ListKeysPendingDeletion(bg, when.Add(time.Hour)); containsRef(refs, doomed.ID) {
			t.Fatal("destroyed key still pending")
		}
	})
}

func containsRef(refs []store.KeyRef, id string) bool {
	for _, r := range refs {
		if r.KeyID == id {
			return true
		}
	}
	return false
}
