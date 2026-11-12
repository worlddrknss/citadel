package store

import "context"

// actorCtxKey carries the authenticated identity performing a write, so the
// store can stamp "who wrote this" columns (secret versions' created_by, a
// secret's updated_by) without every method growing an actor parameter.
type actorCtxKey struct{}

// WithActor returns a child context naming the authenticated identity (a
// console username, access-key ID or principal ARN) on whose behalf store
// writes are made. An empty actor leaves ctx unchanged.
func WithActor(ctx context.Context, actor string) context.Context {
	if actor == "" {
		return ctx
	}
	return context.WithValue(ctx, actorCtxKey{}, actor)
}

// ActorFromContext returns the identity set by WithActor, or "".
func ActorFromContext(ctx context.Context) string {
	v, _ := ctx.Value(actorCtxKey{}).(string)
	return v
}
