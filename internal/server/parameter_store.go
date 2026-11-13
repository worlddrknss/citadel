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
