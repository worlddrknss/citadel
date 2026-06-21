package main

import (
	"context"
	"fmt"
)

// internalSignerFunc performs cryptographic signing for certificate operations
type internalSignerFunc func(ctx context.Context, keyID, algorithm string, digest []byte) ([]byte, error)

// newInternalSigner creates a signing function that uses the KMS engine
func newInternalSigner(store keyStore) internalSignerFunc {
	return func(ctx context.Context, keyID, algorithm string, digest []byte) ([]byte, error) {
		// Resolve the key
		key, err := store.ResolveByID(ctx, keyID)
		if err != nil {
			return nil, fmt.Errorf("resolve key: %w", err)
		}

		// Sign the digest using the internal asymmetric signing logic
		sig, err := signDigestWithKey(key, algorithm, digest)
		if err != nil {
			return nil, fmt.Errorf("sign digest: %w", err)
		}

		return sig, nil
	}
}
