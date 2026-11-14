package sdkgotest_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/servertest"
	"github.com/worlddrknss/citadel/internal/store"
	citadel "github.com/worlddrknss/citadel/sdk/citadel/v2"
)

func TestAgentAccessRequestsAndLeases(t *testing.T) {
	env := servertest.New(t)
	ctx := context.Background()
	editor := newClient(t, env, env.Editor)

	a, err := editor.CreateAgent(ctx, citadel.CreateAgentInput{Name: "coder"})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := editor.CreateAgentToken(ctx, a.AgentID, "ci", 1)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := citadel.New(citadel.Config{BaseURL: env.URL, AgentToken: tok.Token, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	req, err := agent.AgentRequestAccess(ctx, citadel.AgentAccessInput{Credential: "api", Reason: "deploy", Duration: 15 * time.Minute, TaskID: "run-1"})
	if err != nil || req.Status != citadel.AccessRequestPending || req.DurationSeconds != 900 || req.TaskID != "run-1" || req.Origin != "agent" {
		t.Fatalf("AgentRequestAccess = %+v, %v", req, err)
	}
	again, err := agent.AgentRequestAccess(ctx, citadel.AgentAccessInput{Credential: "api", Reason: "deploy", TaskID: "run-1"})
	if err != nil || again.RequestID != req.RequestID {
		t.Fatalf("second request = %+v, %v", again, err)
	}
	pending, err := editor.ListAgentAccessRequests(ctx, a.AgentID, true)
	if err != nil || len(pending) != 1 || pending[0].AgentName != "coder" || pending[0].CanDecide {
		t.Fatalf("ListAgentAccessRequests = %+v, %v (access keys must not be able to decide)", pending, err)
	}

	// A person approves in the console (simulated in the store).
	now := time.Now().UTC().Truncate(time.Second)
	lease := store.AgentLease{AccountID: env.AccountID, LeaseID: store.NewAgentLeaseID(), AgentID: a.AgentID, Credential: "api", Actions: []string{"use"},
		Scope: store.AgentLeaseDuration, ExpiresAt: now.Add(15 * time.Minute), CreatedAt: now, CreatedBy: "admin"}
	if _, err := env.Store.DecideAgentAccessRequest(ctx, env.AccountID, req.RequestID, store.AgentAccessDecision{Status: store.AgentRequestApproved, By: "admin", At: now, Lease: &lease}); err != nil {
		t.Fatal(err)
	}
	got, err := agent.WaitForAgentAccess(ctx, req.RequestID, 10*time.Millisecond)
	if err != nil || got.Status != citadel.AccessRequestApproved || got.Lease == nil || got.Lease.LeaseID != lease.LeaseID || got.Lease.UsesLeft != nil {
		t.Fatalf("WaitForAgentAccess = %+v, %v", got, err)
	}
	leases, err := agent.AgentLeases(ctx, "api")
	if err != nil || len(leases) != 1 || leases[0].Status != "active" {
		t.Fatalf("AgentLeases = %+v, %v", leases, err)
	}
	ended, err := editor.RevokeAgentLease(ctx, lease.LeaseID, "done")
	if err != nil || ended.Status != "ended" || ended.EndedBy == "" {
		t.Fatalf("RevokeAgentLease = %+v, %v", ended, err)
	}
	if all, _ := editor.ListAgentLeases(ctx, a.AgentID, false); len(all) != 1 {
		t.Fatalf("ListAgentLeases = %+v", all)
	}
	if active, _ := agent.AgentLeases(ctx, ""); len(active) != 0 {
		t.Fatalf("active after revoke = %+v", active)
	}

	// A denial ends the wait with ErrAccessDenied and the reason.
	req, err = agent.AgentRequestAccess(ctx, citadel.AgentAccessInput{Credential: "api", Actions: []string{"reveal"}, Reason: "debug"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.Store.DecideAgentAccessRequest(ctx, env.AccountID, req.RequestID, store.AgentAccessDecision{Status: store.AgentRequestDenied, By: "admin", Comment: "use the broker", At: now}); err != nil {
		t.Fatal(err)
	}
	got, err = agent.WaitForAgentAccess(ctx, req.RequestID, 10*time.Millisecond)
	if !errors.Is(err, citadel.ErrAccessDenied) || got.Status != citadel.AccessRequestDenied || got.DecisionComment != "use the broker" {
		t.Fatalf("denied wait = %+v, %v", got, err)
	}
}
