package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

const serviceRootPurpose = "root"

func serviceKeyAAD(purpose string) string { return "service-key:" + purpose }

// loadServiceRoot returns the deployment root secret, creating it on first
// use. Its first value is the wrapping key at that moment, so every key
// previously derived from the wrapping key keeps its value across the
// upgrade; after that it never changes, whatever happens to the wrapping key.
//
// Creating it while retired wrapping keys are configured is refused: the
// keys derived so far came from whichever key was current before the
// rotation, and guessing would silently break audit verification and sealed
// values. Upgrade first, then rotate.
func (s *Store) loadServiceRoot(ctx context.Context) ([]byte, error) {
	root, err := s.readServiceKey(ctx, serviceRootPurpose)
	if err == nil {
		return root, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if len(s.previousWrappingKeys) > 0 {
		return nil, errors.New("the deployment root secret does not exist yet and KMS_PREVIOUS_WRAPPING_KEYS_B64 is set: start this version once with the current wrapping key and no previous keys, then rotate")
	}
	if len(s.wrappingKey) != 32 {
		return nil, errors.New("wrapping key is not configured")
	}
	wrapped, nonce, err := s.wrapKeyMaterial(serviceKeyAAD(serviceRootPurpose), s.wrappingKey)
	if err != nil {
		return nil, err
	}
	// Several replicas may race to create it; the first insert wins.
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO service_keys (purpose, key_wrapped_b64, key_nonce_b64) VALUES ($1, $2, $3) ON CONFLICT (purpose) DO NOTHING`,
		serviceRootPurpose, wrapped, nonce); err != nil {
		return nil, err
	}
	return s.readServiceKey(ctx, serviceRootPurpose)
}

func (s *Store) readServiceKey(ctx context.Context, purpose string) ([]byte, error) {
	var wrapped, nonce string
	err := s.db.QueryRowContext(ctx, `SELECT key_wrapped_b64, key_nonce_b64 FROM service_keys WHERE purpose = $1`, purpose).Scan(&wrapped, &nonce)
	if err != nil {
		return nil, err
	}
	key, err := s.unwrapKeyMaterial(serviceKeyAAD(purpose), wrapped, nonce)
	if err != nil {
		return nil, fmt.Errorf("unwrap service key %q: %w", purpose, err)
	}
	return key, nil
}

// ServiceRoot is the deployment root secret that per-purpose keys are
// derived from. Before Open has loaded it (stores built with New, in tests)
// it is the wrapping key, which is also its initial value.
func (s *Store) ServiceRoot() []byte {
	if len(s.serviceRoot) > 0 {
		return s.serviceRoot
	}
	return s.wrappingKey
}
