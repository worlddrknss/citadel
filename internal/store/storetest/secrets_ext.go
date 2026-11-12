// Package storetest holds backend-independent conformance tests that both the
// memory and postgres store packages run against their implementations, so
// the two backends are held to the same behaviour.
package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// KeyFunc returns a KMS key ID usable for secrets in ctx's account.
type KeyFunc func(t *testing.T, ctx context.Context) string

const (
	acctA = "111111111111"
	acctB = "222222222222"
)

// RunSecretsExtensions exercises ApprovalStore, SecretSettingsStore,
// SecretLifecycleStore, ParameterVersionStore and parameter tenant isolation.
func RunSecretsExtensions(t *testing.T, st store.Store, keyFor KeyFunc) {
	ctxA := store.WithCallerAccount(context.Background(), acctA)
	ctxB := store.WithCallerAccount(context.Background(), acctB)

	t.Run("ApprovalPolicies", func(t *testing.T) {
		if err := st.PutApprovalPolicy(ctxA, store.ApprovalPolicy{Project: "pay", Env: "prod", ApprovalsRequired: 2, ApproverRoles: []string{"admin", "editor"}, UpdatedBy: "alice"}); err != nil {
			t.Fatal(err)
		}
		p, ok, err := st.GetApprovalPolicy(ctxA, "pay", "prod")
		if err != nil || !ok || p.ApprovalsRequired != 2 || len(p.ApproverRoles) != 2 || p.UpdatedBy != "alice" {
			t.Fatalf("GetApprovalPolicy = %+v %v %v", p, ok, err)
		}
		if _, ok, _ := st.GetApprovalPolicy(ctxB, "pay", "prod"); ok {
			t.Fatal("account B sees account A's policy")
		}
		if list, _ := st.ListApprovalPolicies(ctxB); len(list) != 0 {
			t.Fatalf("account B lists %v", list)
		}
		if list, _ := st.ListApprovalPolicies(ctxA); len(list) != 1 {
			t.Fatalf("account A lists %v", list)
		}
		if err := st.PutApprovalPolicy(ctxA, store.ApprovalPolicy{Project: "pay", Env: "prod", ApprovalsRequired: 0}); err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := st.GetApprovalPolicy(ctxA, "pay", "prod"); ok {
			t.Fatal("policy not removed by approvalsRequired 0")
		}
	})

	t.Run("ChangeRequests", func(t *testing.T) {
		cr, err := st.CreateChangeRequest(ctxA, store.ChangeRequestRecord{
			ID: "cr-test-1", Project: "pay", Env: "prod", Path: "/db", Key: "PASSWORD",
			Requester: "alice", RequesterRole: "editor", Comment: "rotate",
			ProposedCiphertext: "c2VhbGVk", ProposedKMSKeyID: "k1", ProposedLength: 6,
		})
		if err != nil {
			t.Fatal(err)
		}
		if cr.Status != store.ChangeRequestPending {
			t.Fatalf("status %q", cr.Status)
		}
		if _, err := st.GetChangeRequest(ctxB, cr.ID); !errors.Is(err, store.ErrChangeRequestNotFound) {
			t.Fatalf("account B GetChangeRequest err = %v", err)
		}
		if list, _ := st.ListChangeRequests(ctxB); len(list) != 0 {
			t.Fatalf("account B lists %v", list)
		}
		if _, err := st.AddChangeRequestApproval(ctxB, cr.ID, store.ChangeRequestApproval{Username: "mallory"}); !errors.Is(err, store.ErrChangeRequestNotFound) {
			t.Fatalf("account B approval err = %v", err)
		}
		got, err := st.AddChangeRequestApproval(ctxA, cr.ID, store.ChangeRequestApproval{Username: "bob", Comment: "lgtm"})
		if err != nil || len(got.Approvals) != 1 || got.Approvals[0].Comment != "lgtm" {
			t.Fatalf("AddChangeRequestApproval = %+v, %v", got, err)
		}
		if _, err := st.AddChangeRequestApproval(ctxA, cr.ID, store.ChangeRequestApproval{Username: "bob"}); !errors.Is(err, store.ErrAlreadyApproved) {
			t.Fatalf("second approval by bob err = %v", err)
		}
		if _, err := st.TransitionChangeRequest(ctxB, cr.ID, store.ChangeRequestPending, store.ChangeRequestApproved, "mallory", ""); err == nil {
			t.Fatal("account B transitioned account A's request")
		}
		dec, err := st.TransitionChangeRequest(ctxA, cr.ID, store.ChangeRequestPending, store.ChangeRequestApproved, "carol", "ship it")
		if err != nil || dec.Status != store.ChangeRequestApproved || dec.DecidedBy != "carol" || dec.DecisionComment != "ship it" || dec.DecidedAt == nil {
			t.Fatalf("TransitionChangeRequest = %+v, %v", dec, err)
		}
		if _, err := st.TransitionChangeRequest(ctxA, cr.ID, store.ChangeRequestPending, store.ChangeRequestRejected, "dave", ""); !errors.Is(err, store.ErrChangeRequestDecided) {
			t.Fatalf("double decision err = %v", err)
		}
		if _, err := st.AddChangeRequestApproval(ctxA, cr.ID, store.ChangeRequestApproval{Username: "erin"}); !errors.Is(err, store.ErrChangeRequestDecided) {
			t.Fatalf("approval after decision err = %v", err)
		}
		back, err := st.TransitionChangeRequest(ctxA, cr.ID, store.ChangeRequestApproved, store.ChangeRequestPending, "", "")
		if err != nil || back.DecidedBy != "" || back.DecidedAt != nil {
			t.Fatalf("reopen = %+v, %v", back, err)
		}
		list, err := st.ListChangeRequests(ctxA)
		if err != nil || len(list) != 1 || list[0].ProposedCiphertext != "c2VhbGVk" || list[0].Path != "/db" || len(list[0].Approvals) != 1 {
			t.Fatalf("ListChangeRequests = %+v, %v", list, err)
		}
	})

	t.Run("SecretSettings", func(t *testing.T) {
		if got, err := st.GetSecretSettings(ctxA); err != nil || got.ViewersCanReveal {
			t.Fatalf("default settings = %+v, %v (viewers must not reveal by default)", got, err)
		}
		if err := st.PutSecretSettings(ctxA, store.SecretSettings{ViewersCanReveal: true, UpdatedBy: "admin"}); err != nil {
			t.Fatal(err)
		}
		if got, _ := st.GetSecretSettings(ctxA); !got.ViewersCanReveal || got.UpdatedBy != "admin" {
			t.Fatalf("settings after put = %+v", got)
		}
		if got, _ := st.GetSecretSettings(ctxB); got.ViewersCanReveal {
			t.Fatal("account B inherits account A's setting")
		}
	})

	t.Run("RenameSecret", func(t *testing.T) {
		key := keyFor(t, ctxA)
		if _, _, err := st.CreateSecret(ctxA, store.CreateSecretRequest{Name: "mv/dev/A", KMSKeyID: key, SecretString: "v1"}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.PutSecretValue(ctxA, store.PutSecretValueRequest{SecretID: "mv/dev/A", SecretString: "v2"}); err != nil {
			t.Fatal(err)
		}
		if err := st.TagSecret(ctxA, "mv/dev/A", []store.SecretTag{{Key: "t", Value: "1"}}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := st.CreateSecret(ctxA, store.CreateSecretRequest{Name: "mv/dev/TAKEN", KMSKeyID: key, SecretString: "x"}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.RenameSecret(ctxA, "mv/dev/A", "mv/dev/TAKEN"); !errors.Is(err, store.ErrSecretExists) {
			t.Fatalf("rename onto existing err = %v", err)
		}
		if _, err := st.RenameSecret(ctxB, "mv/dev/A", "mv/dev/B"); err == nil {
			t.Fatal("account B renamed account A's secret")
		}
		meta, err := st.RenameSecret(ctxA, "mv/dev/A", "mv/dev/sub/A")
		if err != nil || meta.Name != "mv/dev/sub/A" {
			t.Fatalf("RenameSecret = %+v, %v", meta, err)
		}
		if _, err := st.DescribeSecret(ctxA, "mv/dev/A"); err == nil {
			t.Fatal("old name still resolves")
		}
		versions, err := st.ListSecretVersionIDs(ctxA, "mv/dev/sub/A")
		if err != nil || len(versions) != 2 {
			t.Fatalf("history after rename = %v, %v", versions, err)
		}
		v, err := st.GetSecretValue(ctxA, "mv/dev/sub/A", "", "")
		if err != nil || v.SecretString == nil || *v.SecretString != "v2" {
			t.Fatalf("value after rename = %v, %v", v.SecretString, err)
		}
		d, _ := st.DescribeSecret(ctxA, "mv/dev/sub/A")
		if len(d.Tags) != 1 {
			t.Fatalf("tags after rename = %v", d.Tags)
		}
	})

	t.Run("PurgeExpiredSecrets", func(t *testing.T) {
		keyA, keyB := keyFor(t, ctxA), keyFor(t, ctxB)
		for _, c := range []struct {
			ctx  context.Context
			key  string
			name string
		}{{ctxA, keyA, "purge/dev/OLD"}, {ctxB, keyB, "purge/dev/OLD"}, {ctxA, keyA, "purge/dev/KEEP"}} {
			if _, _, err := st.CreateSecret(c.ctx, store.CreateSecretRequest{Name: c.name, KMSKeyID: c.key, SecretString: "x"}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := st.DeleteSecret(ctxA, "purge/dev/OLD", 7, false); err != nil {
			t.Fatal(err)
		}
		if _, err := st.DeleteSecret(ctxB, "purge/dev/OLD", 30, false); err != nil {
			t.Fatal(err)
		}
		// Eight days later only A's (7-day window) is due.
		purged, err := st.PurgeExpiredSecrets(context.Background(), time.Now().Add(8*24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if len(purged) != 1 || purged[0].AccountID != acctA || purged[0].Name != "purge/dev/OLD" {
			t.Fatalf("purged = %+v", purged)
		}
		if _, err := st.DescribeSecret(ctxA, "purge/dev/OLD"); err == nil {
			t.Fatal("purged secret still exists")
		}
		if _, err := st.DescribeSecret(ctxB, "purge/dev/OLD"); err != nil {
			t.Fatalf("account B's secret purged early: %v", err)
		}
		if _, err := st.DescribeSecret(ctxA, "purge/dev/KEEP"); err != nil {
			t.Fatalf("live secret purged: %v", err)
		}
	})

	t.Run("ParameterVersions", func(t *testing.T) {
		rec, err := st.PutParameter(ctxA, store.ParameterRecord{Name: "/app/url", Type: "String", Value: "a", Tier: "Standard"}, false)
		if err != nil {
			t.Fatal(err)
		}
		next := rec
		next.Value = "b"
		if _, err := st.UpdateParameter(ctxA, next, rec.Version+1); !errors.Is(err, store.ErrParameterVersionConflict) {
			t.Fatalf("stale update err = %v", err)
		}
		if _, err := st.UpdateParameter(ctxB, next, rec.Version); !errors.Is(err, store.ErrParameterNotFound) {
			t.Fatalf("account B update err = %v", err)
		}
		got, err := st.UpdateParameter(ctxA, next, rec.Version)
		if err != nil || got.Version != rec.Version+1 || got.Value != "b" {
			t.Fatalf("UpdateParameter = %+v, %v", got, err)
		}
		if _, err := st.UpdateParameter(ctxA, next, rec.Version); !errors.Is(err, store.ErrParameterVersionConflict) {
			t.Fatalf("replayed update err = %v", err)
		}
		if _, err := st.LabelParameterVersion(ctxA, "/app/url", 1, []string{"stable", "old"}); err != nil {
			t.Fatal(err)
		}
		removed, err := st.UnlabelParameterVersion(ctxA, "/app/url", 1, []string{"old", "missing"})
		if err != nil || len(removed) != 1 || removed[0] != "old" {
			t.Fatalf("UnlabelParameterVersion = %v, %v", removed, err)
		}
		hist, _ := st.GetParameterHistory(ctxA, "/app/url")
		if len(hist) != 2 || len(hist[0].Labels) != 1 || hist[0].Labels[0] != "stable" {
			t.Fatalf("history after unlabel = %+v", hist)
		}
		if _, err := st.UnlabelParameterVersion(ctxB, "/app/url", 1, []string{"stable"}); !errors.Is(err, store.ErrParameterNotFound) {
			t.Fatalf("account B unlabel err = %v", err)
		}
		if _, err := st.UnlabelParameterVersion(ctxA, "/app/url", 9, []string{"stable"}); !errors.Is(err, store.ErrParameterNotFound) {
			t.Fatalf("unknown version err = %v", err)
		}
	})

	t.Run("ParameterIsolation", func(t *testing.T) {
		if _, err := st.PutParameter(ctxA, store.ParameterRecord{Name: "/iso/x", Type: "String", Value: "a-only", Tier: "Standard"}, false); err != nil {
			t.Fatal(err)
		}
		if _, err := st.GetParameter(ctxB, "/iso/x"); !errors.Is(err, store.ErrParameterNotFound) {
			t.Fatalf("account B reads account A's parameter: %v", err)
		}
		list, _ := st.ListParameters(ctxB)
		for _, p := range list {
			if p.Name == "/iso/x" {
				t.Fatal("account B lists account A's parameter")
			}
		}
		if _, err := st.PutParameter(ctxB, store.ParameterRecord{Name: "/iso/x", Type: "String", Value: "b", Tier: "Standard"}, false); err != nil {
			t.Fatalf("account B cannot use a name account A uses: %v", err)
		}
		if err := st.DeleteParameter(ctxB, "/iso/x"); err != nil {
			t.Fatal(err)
		}
		if p, err := st.GetParameter(ctxA, "/iso/x"); err != nil || p.Value != "a-only" {
			t.Fatalf("account A's parameter after B's delete = %+v, %v", p, err)
		}
	})
}
