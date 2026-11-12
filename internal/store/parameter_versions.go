package store

import (
	"context"
	"errors"
)

// ErrParameterVersionConflict is returned by UpdateParameter when the stored
// version no longer matches the version the caller edited.
var ErrParameterVersionConflict = errors.New("parameter version conflict")

// ParameterVersionStore adds optimistic-concurrency edits and label removal to
// ParameterStore. Both are scoped to the caller account like the rest of it.
type ParameterVersionStore interface {
	// UpdateParameter replaces an existing parameter with rec (writing a new
	// version) only if its current version is expectedVersion; otherwise it
	// returns ErrParameterVersionConflict. A missing parameter returns
	// ErrParameterNotFound. The check and the write are atomic.
	UpdateParameter(ctx context.Context, rec ParameterRecord, expectedVersion int64) (ParameterRecord, error)
	// UnlabelParameterVersion detaches labels from one version and returns
	// the ones that were attached (and so removed). Labels not on that
	// version are ignored.
	UnlabelParameterVersion(ctx context.Context, name string, version int64, labels []string) ([]string, error)
}
