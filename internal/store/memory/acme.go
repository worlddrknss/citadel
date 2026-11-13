package memory

import (
	"context"

	"github.com/worlddrknss/citadel/internal/store"
)

// The in-memory store's ACME (Let's Encrypt) implementations are unsupported: the
// feature requires the database-backed wrapping path.
func (s *Store) GetACMELEAccount(_ context.Context, _ string) (store.ACMELEAccount, error) {
	return store.ACMELEAccount{}, store.ErrUnsupported
}

func (s *Store) UpsertACMELEAccount(_ context.Context, _ store.ACMELEAccount) error {
	return store.ErrUnsupported
}

func (s *Store) CreateACMELECertificate(_ context.Context, _ store.ACMELECertificate) error {
	return store.ErrUnsupported
}

func (s *Store) GetACMELECertificate(_ context.Context, _ string) (store.ACMELECertificate, error) {
	return store.ACMELECertificate{}, store.ErrUnsupported
}

func (s *Store) ListACMELECertificates(_ context.Context) ([]store.ACMELECertificate, error) {
	return nil, store.ErrUnsupported
}

func (s *Store) CreateACMELEOrder(_ context.Context, _ store.ACMELEOrder) error {
	return store.ErrUnsupported
}

func (s *Store) GetACMELEOrder(_ context.Context, _ string) (store.ACMELEOrder, error) {
	return store.ACMELEOrder{}, store.ErrUnsupported
}

func (s *Store) DeleteACMELEOrder(_ context.Context, _ string) error {
	return store.ErrUnsupported
}

func (s *Store) UpdateACMELEOrder(_ context.Context, _ store.ACMELEOrder) error {
	return store.ErrUnsupported
}

func (s *Store) TransitionACMELEOrder(_ context.Context, _ string, _ []string, _, _ string) (bool, error) {
	return false, store.ErrUnsupported
}
