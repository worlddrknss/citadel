package main

import (
	"context"
	"fmt"
)

// callerAccountCtxKey is the private context key under which the authenticated
// caller's 12-digit account ID is stored after a successful DB-backed SigV4
// verification. Using an unexported type prevents collisions and stops callers
// from spoofing the value through string headers.
type callerAccountCtxKey struct{}

// withCallerAccount returns a child context carrying the authenticated caller's
// account ID. It is set only after the request's SigV4 signature has been
// cryptographically verified against a stored access-key secret.
func withCallerAccount(ctx context.Context, accountID string) context.Context {
	if accountID == "" {
		return ctx
	}
	return context.WithValue(ctx, callerAccountCtxKey{}, accountID)
}

// callerAccountFromContext returns the authenticated caller account ID, if one
// was attached by the SigV4 auth layer. Admin UI sessions and non-strict API
// requests carry no caller account, so isolation is a no-op for them.
func callerAccountFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(callerAccountCtxKey{}).(string)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// accountFilter returns an SQL boolean condition (without a leading AND/WHERE)
// and its bound argument that restrict a query to the caller's account. When no
// caller account is present in the context it returns an empty condition so the
// query is unchanged — this keeps per-account isolation inert until DB-backed
// strict SigV4 is enabled.
func accountFilter(ctx context.Context, column string, argPos int) (cond string, args []any) {
	acct, ok := callerAccountFromContext(ctx)
	if !ok {
		return "", nil
	}
	return fmt.Sprintf("%s = $%d", column, argPos), []any{acct}
}

// accountForContext returns the caller's account ID when present (strict SigV4),
// otherwise the deployment's global account ID. It is used to stamp newly
// created resources and to build their ARNs so that records remain consistent
// whether or not per-account auth is active.
func (s *dbStore) accountForContext(ctx context.Context) string {
	if acct, ok := callerAccountFromContext(ctx); ok {
		return acct
	}
	_, a := s.DeploymentIdentity()
	return a
}

// keyARNForCtx builds a KMS key ARN using the caller's account when available,
// falling back to the deployment account.
func (s *dbStore) keyARNForCtx(ctx context.Context, id string) string {
	r, _ := s.DeploymentIdentity()
	return arnFor("kms", r, s.accountForContext(ctx), "key/"+id)
}

// secretARNForCtx builds a Secrets Manager ARN using the caller's account when
// available, falling back to the deployment account.
func (s *dbStore) secretARNForCtx(ctx context.Context, name string) string {
	r, _ := s.DeploymentIdentity()
	return arnFor("secretsmanager", r, s.accountForContext(ctx), "secret:"+name)
}
