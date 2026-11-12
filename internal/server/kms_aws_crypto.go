package server

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/worlddrknss/citadel/internal/store"
)

// writeKMSOpError writes err as an AWS error: kmsOpError values as-is,
// anything else as an opaque internal failure (logged, never echoed).
func writeKMSOpError(w http.ResponseWriter, err error, fallback string) string {
	var oe *kmsOpError
	if errors.As(err, &oe) {
		writeAWSJSONError(w, http.StatusBadRequest, oe.Type, oe.Message)
		return oe.Type
	}
	slog.Error("kms operation failed", "op", fallback, "err", err)
	writeAWSJSONError(w, http.StatusInternalServerError, "KMSInternalException", fallback)
	return "KMSInternalException"
}

// keyUsable checks a key can serve a cryptographic request.
func keyUsable(key store.KMSKey) error {
	if key.DeletionDate != nil {
		return opErr("KMSInvalidStateException", "key is pending deletion")
	}
	if !key.Enabled {
		return opErr("DisabledException", "key is disabled")
	}
	return nil
}
