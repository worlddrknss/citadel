package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/worlddrknss/citadel/internal/store"
)

// Parameter names follow AWS's documented rules ("Requirements and
// constraints for parameter names" in the Systems Manager user guide, and the
// Name member in the API reference).
const (
	// maxParameterNameInput is the API's length constraint on the Name
	// member, for every operation.
	maxParameterNameInput = 2048
	// maxParameterARNLength bounds a parameter's name including its ARN
	// ("arn:aws:ssm:<region>:<account>:parameter/<name>"). AWS counts the
	// whole ARN, so the name itself can be at most 1011 minus the prefix.
	maxParameterARNLength = 1011
	// maxParameterHierarchyLevels is the deepest hierarchy AWS allows.
	maxParameterHierarchyLevels = 15
)

// Parameter name messages. The console shows the same wording
// (web/src/routes/parameters/api.ts, validateName).
const (
	msgParameterNameReserved = `Parameter names can't begin with "aws" or "ssm" (in any case).`
	msgParameterHierarchy    = "A parameter hierarchy can have a maximum of 15 levels."
	msgParameterNameTooLong  = "Parameter names can be at most %d characters (AWS limits the full ARN, arn:aws:ssm:<region>:<account>:parameter/<name>, to 1011)."
	msgParameterInputTooLong = "1 validation error detected: Value at 'name' failed to satisfy constraint: Member must have length less than or equal to 2048"

	msgSSMParameterReserved   = `Parameter name: can't be prefixed with "aws" or "ssm" (case-insensitive). If formed as a path, it can consist of sub-paths divided by slash symbol; each sub-path can be formed as a mix of letters, numbers and the following 3 symbols .-_`
	msgSSMParameterHierarchy  = "A hierarchy can have a maximum of 15 levels. For more information, see Requirements and constraints for parameter names in the AWS Systems Manager User Guide."
	awsErrHierarchyLevelLimit = "HierarchyLevelLimitExceededException"
)

// parameterNameError is a refused parameter name. awsType is the SSM error
// code (ValidationException when empty); awsMsg, when set, is the SSM wording
// where it differs from the native message.
type parameterNameError struct {
	msg, awsType, awsMsg string
}

func (e *parameterNameError) Error() string { return e.msg }

// ssmNameErrorParts returns the SSM error code and message for a name error.
func ssmNameErrorParts(err error) (string, string) {
	var ne *parameterNameError
	if !errors.As(err, &ne) {
		return "ValidationException", err.Error()
	}
	typ, msg := ne.awsType, ne.awsMsg
	if typ == "" {
		typ = "ValidationException"
	}
	if msg == "" {
		msg = ne.msg
	}
	return typ, msg
}

// normalizeParameterName canonicalizes an SSM-style parameter name to a
// single leading slash with validated path segments and no trailing slash.
// It applies the rules every operation shares (characters, the 2048-character
// input limit, 15 levels); validateNewParameterName adds the rules for
// creating or overwriting a parameter.
func normalizeParameterName(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", errors.New("parameter name is required")
	}
	if len(trimmed) > maxParameterNameInput {
		return "", &parameterNameError{msg: msgParameterInputTooLong}
	}
	// SSM allows a bare relative name (no leading slash) for a top-level
	// parameter; canonicalize everything to a leading slash.
	parts := strings.Split(strings.Trim(trimmed, "/"), "/")
	for _, p := range parts {
		if !nativeSegmentRe.MatchString(p) {
			return "", errors.New("parameter name segments must match [A-Za-z0-9_.-]+")
		}
	}
	if len(parts) > maxParameterHierarchyLevels {
		return "", &parameterNameError{msg: msgParameterHierarchy, awsType: awsErrHierarchyLevelLimit, awsMsg: msgSSMParameterHierarchy}
	}
	return "/" + strings.Join(parts, "/"), nil
}

// reservedParameterName reports whether canonical (as returned by
// normalizeParameterName) begins with "aws" or "ssm" in any case. AWS
// reserves both prefixes for the name, which for a hierarchy means its first
// level: "/aws/x", "/SSM-config" and "awsKey" are refused; "/app/aws" is not.
func reservedParameterName(canonical string) bool {
	first := strings.ToLower(strings.TrimPrefix(canonical, "/"))
	return strings.HasPrefix(first, "aws") || strings.HasPrefix(first, "ssm")
}

// maxParameterNameLength is the longest canonical name (leading slash
// included) whose ARN in region and account fits maxParameterARNLength.
func maxParameterNameLength(region, account string) int {
	return maxParameterARNLength - len("arn:aws:ssm:"+region+":"+account+":parameter")
}

// parameterNameLimit is maxParameterNameLength for the caller's account.
func (s *Server) parameterNameLimit(ctx context.Context) int {
	region, acct := s.store.DeploymentIdentity()
	if a, ok := store.CallerAccountFromContext(ctx); ok {
		acct = a
	}
	return maxParameterNameLength(region, acct)
}

// validateNewParameterName applies the rules for writing a parameter
// (PutParameter and POST /v1/parameters) on top of normalizeParameterName:
// the reserved prefixes and the ARN length. Reads, deletes and in-place edits
// don't, so parameters created before these checks stay reachable.
func (s *Server) validateNewParameterName(ctx context.Context, canonical string) error {
	if reservedParameterName(canonical) {
		return &parameterNameError{msg: msgParameterNameReserved, awsMsg: msgSSMParameterReserved}
	}
	if limit := s.parameterNameLimit(ctx); len(canonical) > limit {
		return &parameterNameError{msg: fmt.Sprintf(msgParameterNameTooLong, limit)}
	}
	return nil
}
