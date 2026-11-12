package memory

import (
	"context"

	"github.com/worlddrknss/citadel/internal/store"
)

// The in-memory store's CA implementations (unsupported)
func (s *Store) CreateCertificateAuthority(_ context.Context, _ store.PCACertificateAuthority) error {
	return store.ErrUnsupported
}

func (s *Store) DescribeCertificateAuthority(_ context.Context, _ string) (store.PCACertificateAuthority, error) {
	return store.PCACertificateAuthority{}, store.ErrUnsupported
}

func (s *Store) ListCertificateAuthorities(_ context.Context) ([]store.PCACertificateAuthority, error) {
	return nil, store.ErrUnsupported
}

func (s *Store) CreateCertificate(_ context.Context, _ store.PCACertificate) error {
	return store.ErrUnsupported
}

func (s *Store) GetCertificate(_ context.Context, _ string) (store.PCACertificate, error) {
	return store.PCACertificate{}, store.ErrUnsupported
}

func (s *Store) ListCertificates(_ context.Context, _ string) ([]store.PCACertificate, error) {
	return nil, store.ErrUnsupported
}

func (s *Store) RevokeCertificate(_ context.Context, _, _ string) error {
	return store.ErrUnsupported
}
