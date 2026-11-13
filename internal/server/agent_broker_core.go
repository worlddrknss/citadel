package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/netip"
	"time"

	"github.com/worlddrknss/citadel/internal/agentbroker"
	"github.com/worlddrknss/citadel/internal/providertoken"
	"github.com/worlddrknss/citadel/internal/store"
)

// serverAgentAccess wires the broker and the MCP server to the agents core:
// agentRequest (authentication, limits, audit principal),
// evaluateAgentAccess (grants, windows, rate limits) and the credential's
// backing secret.
type serverAgentAccess struct{ s *Server }

// agentCoreUse is what evaluate hands to minter.
type agentCoreUse struct {
	ref agentSecretRef
}

func (a serverAgentAccess) authenticate(w http.ResponseWriter, r *http.Request, action string) (*agentCaller, context.Context, bool) {
	p, ctx, ok := a.s.agentRequest(w, r, action)
	if !ok {
		return nil, nil, false
	}
	return &agentCaller{AccountID: p.AccountID, AgentID: p.Agent.AgentID, Name: p.Agent.Name, Owner: p.Agent.Owner, TaskID: p.TaskID, ref: p}, ctx, true
}

func (a serverAgentAccess) principal(c *agentCaller) *AgentPrincipal {
	p, _ := c.ref.(*AgentPrincipal)
	if p == nil {
		return &AgentPrincipal{AccountID: c.AccountID, Agent: store.Agent{AccountID: c.AccountID, AgentID: c.AgentID, Name: c.Name, Owner: c.Owner}}
	}
	cp := *p
	cp.TaskID = c.TaskID // a taskId from the body or tool arguments
	return &cp
}

func (a serverAgentAccess) evaluate(ctx context.Context, c *agentCaller, credential, action string) agentUse {
	p := a.principal(c)
	grant, cred, ref, d := a.s.evaluateAgentAccess(ctx, p.Agent, credential, action, time.Now().UTC())
	if !d.Allowed {
		return agentUse{Reason: d.Reason, RetryAfter: d.RetryAfter}
	}
	return agentUse{
		Allowed:    true,
		Credential: credentialInfo(cred, grant, ""),
		Profile:    brokerProfile(cred),
		ref:        agentCoreUse{ref: ref},
	}
}

func credentialInfo(cred store.AgentCredential, g store.AgentGrant, status string) agentCredentialInfo {
	if status == "" {
		status = "available"
	}
	return agentCredentialInfo{
		Name: cred.Name, Kind: cred.Kind, Description: cred.Description,
		AllowedHosts: nonNil(cred.AllowedHosts), AllowedMethods: cred.AllowedMethods, AllowedPathPrefixes: cred.AllowedPathPrefixes,
		Actions: nonNil(g.Actions), Status: status,
	}
}

// brokerProfile converts a stored usage profile for the broker.
func brokerProfile(c store.AgentCredential) agentbroker.Profile {
	p := agentbroker.Profile{
		Kind: c.Kind, AllowedHosts: c.AllowedHosts, AllowedMethods: c.AllowedMethods, AllowedPathPrefixes: c.AllowedPathPrefixes,
		HeaderName: c.HeaderName, HeaderPrefix: c.HeaderPrefix, QueryParam: c.QueryParam, AllowHTTP: c.AllowHTTP,
	}
	for _, raw := range c.AllowedCIDRs {
		if pfx, err := netip.ParsePrefix(raw); err == nil {
			p.AllowedCIDRs = append(p.AllowedCIDRs, pfx.Masked())
		}
	}
	return p
}

func (a serverAgentAccess) minter(ctx context.Context, c *agentCaller, u agentUse) (providertoken.Minter, error) {
	cu, ok := u.ref.(agentCoreUse)
	if !ok {
		return nil, errors.New("no credential reference")
	}
	v, err := a.s.agentSecretValue(ctx, c.AccountID, cu.ref)
	if err != nil {
		return nil, err
	}
	return providertoken.Static{Value: v}, nil
}

func (a serverAgentAccess) credentials(ctx context.Context, c *agentCaller) ([]agentCredentialInfo, error) {
	grants, err := a.s.store.ListAgentGrants(ctx, c.AccountID, c.AgentID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	out := make([]agentCredentialInfo, 0, len(grants))
	for _, g := range grants {
		cred, err := a.s.store.GetAgentCredential(ctx, c.AccountID, g.Credential)
		if err != nil {
			if !errors.Is(err, store.ErrAgentCredentialNotFound) {
				log.Printf("agent broker: credential read failed: %v", err)
			}
			continue
		}
		status := agentGrantStatus(g, now)
		if status == "" {
			if _, err := a.s.agentSecretRef(ctx, c.AccountID, cred.SecretName); err != nil {
				status = agentDenyCredentialUnavailable
			}
		}
		out = append(out, credentialInfo(cred, g, status))
	}
	return out, nil
}

func (a serverAgentAccess) auditOrigin(r *http.Request, c *agentCaller) store.AuditOrigin {
	return a.s.agentAuditOrigin(r, a.principal(c))
}
