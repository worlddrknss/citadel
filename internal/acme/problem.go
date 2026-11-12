package acme

import (
	"errors"
	"fmt"
	"net/http"
)

// errNS is the RFC 8555 §6.7 error namespace.
const errNS = "urn:ietf:params:acme:error:"

// Problem types used by this server (RFC 8555 §6.7, RFC 8738).
const (
	ProbAccountDoesNotExist     = errNS + "accountDoesNotExist"
	ProbAlreadyRevoked          = errNS + "alreadyRevoked"
	ProbBadCSR                  = errNS + "badCSR"
	ProbBadNonce                = errNS + "badNonce"
	ProbBadPublicKey            = errNS + "badPublicKey"
	ProbBadRevocationReason     = errNS + "badRevocationReason"
	ProbBadSignatureAlgorithm   = errNS + "badSignatureAlgorithm"
	ProbConnection              = errNS + "connection"
	ProbDNS                     = errNS + "dns"
	ProbExternalAccountRequired = errNS + "externalAccountRequired"
	ProbIncorrectResponse       = errNS + "incorrectResponse"
	ProbInvalidContact          = errNS + "invalidContact"
	ProbMalformed               = errNS + "malformed"
	ProbOrderNotReady           = errNS + "orderNotReady"
	ProbRateLimited             = errNS + "rateLimited"
	ProbRejectedIdentifier      = errNS + "rejectedIdentifier"
	ProbServerInternal          = errNS + "serverInternal"
	ProbUnauthorized            = errNS + "unauthorized"
	ProbUnsupportedContact      = errNS + "unsupportedContact"
	ProbUnsupportedIdentifier   = errNS + "unsupportedIdentifier"
)

// Problem is an RFC 7807 problem document as used by ACME (RFC 8555 §6.7).
// It implements error, so Policy, Issuer and Validator implementations may
// return a *Problem to control exactly what the client sees.
type Problem struct {
	Type        string      `json:"type"`
	Detail      string      `json:"detail,omitempty"`
	Status      int         `json:"status,omitempty"`
	Identifier  *Identifier `json:"identifier,omitempty"`
	Subproblems []Problem   `json:"subproblems,omitempty"`
	// Algorithms lists acceptable JWS algorithms on badSignatureAlgorithm.
	Algorithms []string `json:"algorithms,omitempty"`
}

func (p *Problem) Error() string {
	if p.Detail == "" {
		return p.Type
	}
	return p.Type + ": " + p.Detail
}

func newProblem(typ string, status int, format string, args ...any) *Problem {
	return &Problem{Type: typ, Status: status, Detail: fmt.Sprintf(format, args...)}
}

func malformed(format string, args ...any) *Problem {
	return newProblem(ProbMalformed, http.StatusBadRequest, format, args...)
}

func unauthorized(format string, args ...any) *Problem {
	return newProblem(ProbUnauthorized, http.StatusForbidden, format, args...)
}

func notFound(what string) *Problem {
	return newProblem(ProbMalformed, http.StatusNotFound, "%s not found", what)
}

func serverInternal(format string, args ...any) *Problem {
	return newProblem(ProbServerInternal, http.StatusInternalServerError, format, args...)
}

// asProblem converts an arbitrary error into a Problem. Errors that are not
// already Problems become fallback (with the given type and status) so that
// internal details are not leaked unless the implementation chose to.
func asProblem(err error, fallbackType string, fallbackStatus int, detail string) *Problem {
	var p *Problem
	if errors.As(err, &p) {
		cp := *p
		if cp.Status == 0 {
			cp.Status = statusFor(cp.Type)
		}
		return &cp
	}
	return &Problem{Type: fallbackType, Status: fallbackStatus, Detail: detail}
}

func statusFor(typ string) int {
	switch typ {
	case ProbUnauthorized, ProbOrderNotReady:
		return http.StatusForbidden
	case ProbRateLimited:
		return http.StatusTooManyRequests
	case ProbServerInternal:
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}
