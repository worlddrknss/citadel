package store

import (
	"context"
	"errors"
)

// ErrAliasExists is returned by stores that detect a duplicate alias name.
var ErrAliasExists = errors.New("alias already exists")

// AliasPageQuery selects one page of ListAliases.
type AliasPageQuery struct {
	After       string // exclusive cursor: last alias name of the previous page
	Limit       int
	TargetKeyID string // optional: only aliases pointing at this key ID
}

// SecretPageQuery selects one page of secrets ordered by name.
type SecretPageQuery struct {
	After          string // exclusive cursor: last secret name of the previous page
	Limit          int
	IncludeDeleted bool // include secrets scheduled for deletion
}

// ParameterPageQuery selects one page of parameters ordered by name.
type ParameterPageQuery struct {
	// Path restricts results to names under Path ("/" or "" for all). The
	// path itself is not a match, only names below it.
	Path string
	// Recursive includes names more than one level below Path.
	Recursive bool
	After     string // exclusive cursor: last name of the previous page
	Limit     int
}

// AWSPageStore is cursor pagination for the AWS list APIs, done in the store
// rather than by loading every row. Each method returns at most Limit items
// in byte-wise name (or key ID) order and reports whether more remain.
// ListKeysPage returns key metadata only: MasterKeyRaw is not loaded.
type AWSPageStore interface {
	ListKeysPage(ctx context.Context, after string, limit int) ([]KMSKey, bool, error)
	ListAliasesPage(ctx context.Context, q AliasPageQuery) ([]KMSAlias, bool, error)
	ListSecretsPage(ctx context.Context, q SecretPageQuery) ([]SecretMetadataRecord, bool, error)
	ListParametersPage(ctx context.Context, q ParameterPageQuery) ([]ParameterRecord, bool, error)
}

// ParameterPathPrefix returns the name prefix that selects parameters below
// path: "/" for the root, otherwise the path with one trailing slash.
func ParameterPathPrefix(path string) string {
	if path == "" || path == "/" {
		return "/"
	}
	if path[len(path)-1] == '/' {
		return path
	}
	return path + "/"
}

// ParameterInPath reports whether name lies below the path prefix, honouring
// Recursive (one level only when false).
func ParameterInPath(name, prefix string, recursive bool) bool {
	if len(name) <= len(prefix) || name[:len(prefix)] != prefix {
		return false
	}
	if recursive {
		return true
	}
	for _, c := range name[len(prefix):] {
		if c == '/' {
			return false
		}
	}
	return true
}
