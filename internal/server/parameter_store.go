package server

import (
	"errors"
	"strings"
)

// Parameter Store provides an AWS Systems Manager (SSM) Parameter Store
// compatible configuration surface. Parameters are hierarchical, slash-style
// paths (e.g. "/app/prod/db/password") and may be of type String, StringList,
// or SecureString. SecureString values are encrypted at rest with a KMS key
// (defaulting to the deployment's default key when none is supplied), mirroring
// the Secrets Manager ciphertext format so the existing crypto helpers can be
// reused.

const (
	parameterTypeString       = "String"
	parameterTypeStringList   = "StringList"
	parameterTypeSecureString = "SecureString"
	parameterTierStandard     = "Standard"
	parameterTierAdvanced     = "Advanced"
)

// normalizeParameterName canonicalizes an SSM-style parameter name to a single
// leading slash with validated path segments and no trailing slash.
func normalizeParameterName(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", errors.New("parameter name is required")
	}
	// SSM allows a bare relative name (no leading slash) for a top-level
	// parameter; canonicalize everything to a leading slash.
	parts := strings.Split(strings.Trim(trimmed, "/"), "/")
	if len(parts) == 0 {
		return "", errors.New("parameter name is required")
	}
	for _, p := range parts {
		if !nativeSegmentRe.MatchString(p) {
			return "", errors.New("parameter name segments must match [A-Za-z0-9_.-]+")
		}
	}
	if len(parts) > 15 {
		return "", errors.New("parameter name hierarchy is too deep")
	}
	return "/" + strings.Join(parts, "/"), nil
}

func normalizeParameterType(t string) (string, error) {
	switch strings.TrimSpace(t) {
	case "", parameterTypeString:
		return parameterTypeString, nil
	case parameterTypeStringList:
		return parameterTypeStringList, nil
	case parameterTypeSecureString:
		return parameterTypeSecureString, nil
	default:
		return "", errors.New("Type must be String, StringList, or SecureString")
	}
}

func normalizeParameterTier(t string) string {
	if strings.TrimSpace(t) == parameterTierAdvanced {
		return parameterTierAdvanced
	}
	return parameterTierStandard
}

// ---- dbStore implementation -----------------------------------------------

// ---- inMemoryStore implementation -----------------------------------------

// ---- label helpers ---------------------------------------------------------
