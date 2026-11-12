package main

import (
	"context"

	"github.com/worlddrknss/citadel/internal/arn"
	"github.com/worlddrknss/citadel/internal/store"
)

// accountForContext returns the caller's account ID when present (strict SigV4),
// otherwise the deployment's global account ID. It is used to stamp newly
// created resources and to build their ARNs so that records remain consistent
// whether or not per-account auth is active.
func (s *dbStore) accountForContext(ctx context.Context) string {
	if acct, ok := store.CallerAccountFromContext(ctx); ok {
		return acct
	}
	_, a := s.DeploymentIdentity()
	return a
}

// keyARNForCtx builds a KMS key ARN using the caller's account when available,
// falling back to the deployment account.
func (s *dbStore) keyARNForCtx(ctx context.Context, id string) string {
	r, _ := s.DeploymentIdentity()
	return arn.Build("kms", r, s.accountForContext(ctx), "key/"+id)
}

// secretARNForCtx builds a Secrets Manager ARN using the caller's account when
// available, falling back to the deployment account.
func (s *dbStore) SecretARNForCtx(ctx context.Context, name string) string {
	r, _ := s.DeploymentIdentity()
	return arn.Build("secretsmanager", r, s.accountForContext(ctx), "secret:"+name)
}

// accountForContext returns the caller's account ID when present, otherwise the
// deployment's global account ID. The in-memory store mirrors the dbStore
// behaviour so per-account isolation is identical across both backends.
func (s *inMemoryStore) accountForContext(ctx context.Context) string {
	if acct, ok := store.CallerAccountFromContext(ctx); ok {
		return acct
	}
	_, a := s.DeploymentIdentity()
	return a
}

// secretARNForCtx builds a Secrets Manager ARN for the in-memory store using
// the caller's account when available, falling back to the deployment account.
func (s *inMemoryStore) SecretARNForCtx(ctx context.Context, name string) string {
	r, _ := s.DeploymentIdentity()
	return arn.Build("secretsmanager", r, s.accountForContext(ctx), "secret:"+name)
}
