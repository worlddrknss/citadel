package store

import (
	"context"
	"errors"
	"strings"
	"time"
)

var (
	ErrParameterNotFound = errors.New("parameter not found")
	ErrParameterExists   = errors.New("parameter already exists")
)

// ParameterRecord is the persisted form of a parameter. For SecureString the
// Value field holds the base64 ciphertext blob; for String/StringList it holds
// the plaintext value.
type ParameterRecord struct {
	Name        string
	Type        string
	Value       string
	IsEncrypted bool
	KMSKeyID    string
	Tier        string
	Version     int64
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ParameterHistoryEntry captures a single historical version of a parameter.
type ParameterHistoryEntry struct {
	Name        string
	Version     int64
	Type        string
	Value       string
	IsEncrypted bool
	KMSKeyID    string
	Tier        string
	Description string
	Labels      []string
	ModifiedAt  time.Time
}

type ParamTag struct {
	Key   string
	Value string
}

// ParameterStore is the persistence contract for Parameter Store. Both
// backends implement it; it is part of Store, though the SSM handlers still
// reach it through a type assertion.
type ParameterStore interface {
	PutParameter(ctx context.Context, rec ParameterRecord, overwrite bool) (ParameterRecord, error)
	GetParameter(ctx context.Context, name string) (ParameterRecord, error)
	ListParameters(ctx context.Context) ([]ParameterRecord, error)
	DeleteParameter(ctx context.Context, name string) error
	GetParameterHistory(ctx context.Context, name string) ([]ParameterHistoryEntry, error)
	LabelParameterVersion(ctx context.Context, name string, version int64, labels []string) ([]string, error)
	TagParameter(ctx context.Context, name string, tags []ParamTag) error
	UntagParameter(ctx context.Context, name string, keys []string) error
	ListParameterTags(ctx context.Context, name string) ([]ParamTag, error)
}

func MergeLabels(existing, add []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(existing)+len(add))
	for _, l := range existing {
		if _, ok := seen[l]; !ok {
			seen[l] = struct{}{}
			out = append(out, l)
		}
	}
	for _, l := range add {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if _, ok := seen[l]; !ok {
			seen[l] = struct{}{}
			out = append(out, l)
		}
	}
	return out
}

func RemoveLabel(labels []string, target string) []string {
	out := make([]string, 0, len(labels))
	for _, l := range labels {
		if l != target {
			out = append(out, l)
		}
	}
	return out
}
