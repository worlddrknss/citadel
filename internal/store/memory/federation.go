package memory

import (
	"context"

	"github.com/worlddrknss/citadel/internal/store"
)

func (s *Store) CreateOIDCProvider(context.Context, store.OIDCProvider) error {
	return store.ErrUnsupported
}

func (s *Store) ListOIDCProviders(context.Context, string) ([]store.OIDCProvider, error) {
	return nil, store.ErrUnsupported
}

func (s *Store) GetOIDCProviderByURL(context.Context, string, string) (store.OIDCProvider, error) {
	return store.OIDCProvider{}, store.ErrUnsupported
}

func (s *Store) DeleteOIDCProvider(context.Context, string, string) error {
	return store.ErrUnsupported
}

func (s *Store) CreateIAMRole(context.Context, store.IAMRole) error {
	return store.ErrUnsupported
}

func (s *Store) ListIAMRoles(context.Context, string) ([]store.IAMRole, error) {
	return nil, store.ErrUnsupported
}

func (s *Store) GetIAMRole(context.Context, string, string) (store.IAMRole, error) {
	return store.IAMRole{}, store.ErrUnsupported
}

func (s *Store) GetIAMRoleByARN(context.Context, string) (store.IAMRole, error) {
	return store.IAMRole{}, store.ErrUnsupported
}

func (s *Store) DeleteIAMRole(context.Context, string, string) error {
	return store.ErrUnsupported
}

func (s *Store) CreateSTSSession(context.Context, store.STSSession, string, string) error {
	return store.ErrUnsupported
}

func (s *Store) DeleteExpiredSTSSessions(context.Context) (int64, error) {
	return 0, store.ErrUnsupported
}
