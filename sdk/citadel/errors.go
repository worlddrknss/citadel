package citadel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Error codes the API returns in APIError.Code. The list is not exhaustive:
// operations have their own codes too (for example "create_failed").
const (
	CodeInvalidRequest   = "invalid_request"
	CodeUnauthorized     = "unauthorized"
	CodeForbidden        = "forbidden"
	CodeNotFound         = "not_found"
	CodeAlreadyExists    = "already_exists"
	CodeApprovalRequired = "approval_required"
	CodeRevealForbidden  = "reveal_forbidden"
	CodeVersionConflict  = "version_conflict"
	CodeRateLimited      = "rate_limited"
	CodeKeyDisabled      = "key_disabled"
	CodeInvalidState     = "invalid_state"
	CodeInternalError    = "internal_error"
)

// APIError is a non-2xx response from the API. The API's error body is
// {"error": "<code>", "message": "<text>"}; Code is the stable,
// machine-readable part.
type APIError struct {
	// StatusCode is the HTTP status.
	StatusCode int
	// Code is the API error code, such as "not_found" (see the Code
	// constants). It is "http_<status>" when the body was not an API error.
	Code string
	// Message is the human-readable explanation.
	Message string
	// Method and Path identify the call.
	Method, Path string
	// RetryAfter is the server's Retry-After hint, when it sent one.
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	return fmt.Sprintf("citadel: %s %s: %d %s: %s", e.Method, e.Path, e.StatusCode, e.Code, e.Message)
}

func newAPIError(method, path string, resp *rawResponse) *APIError {
	e := &APIError{StatusCode: resp.status, Method: method, Path: path, RetryAfter: parseRetryAfter(resp.header.Get("Retry-After"))}
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(resp.body, &body) == nil && body.Error != "" {
		e.Code, e.Message = body.Error, body.Message
	} else {
		e.Code = fmt.Sprintf("http_%d", resp.status)
		e.Message = http.StatusText(resp.status)
	}
	return e
}

// ErrorCode returns the API error code of err (an *APIError, possibly
// wrapped), or "" when err is not an API error.
func ErrorCode(err error) string {
	var e *APIError
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// IsNotFound reports whether err is a 404 from the API.
func IsNotFound(err error) bool { return statusOf(err) == http.StatusNotFound }

// IsUnauthorized reports whether the access key was missing, wrong or
// inactive (401).
func IsUnauthorized(err error) bool { return statusOf(err) == http.StatusUnauthorized }

// IsForbidden reports whether the key's owner lacks the role for the call
// (403), including reveal_forbidden.
func IsForbidden(err error) bool { return statusOf(err) == http.StatusForbidden }

// IsApprovalRequired reports whether the change targets an environment with
// an approval policy; submit a change request instead.
func IsApprovalRequired(err error) bool { return ErrorCode(err) == CodeApprovalRequired }

// IsRateLimited reports whether the call was still rate limited after the
// client's retries.
func IsRateLimited(err error) bool { return statusOf(err) == http.StatusTooManyRequests }

func statusOf(err error) int {
	var e *APIError
	if errors.As(err, &e) {
		return e.StatusCode
	}
	return 0
}
