package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/arn"
	"github.com/worlddrknss/citadel/internal/sigv4"
)

// AWS API authentication.
//
// Every AWS-protocol request (KMS, Secrets Manager, SSM, ACM, ACM PCA, STS)
// goes through verifyAWSRequest. There is exactly one way in: a SigV4
// signature that verifies against a known secret. The only exception is
// KMS_INSECURE_DEV, which skips verification entirely for local development
// and must never be set on a shared deployment.

// awsCaller is the identity a verified SigV4 request resolves to.
type awsCaller struct {
	AccessKeyID string
	Username    string
	AccountID   string
	Temporary   bool // STS-issued (ASIA) credentials
}

// PrincipalARN renders the caller as an IAM principal for policy evaluation.
func (c awsCaller) PrincipalARN() string {
	if c.Temporary {
		return arn.Build("sts", "", c.AccountID, "assumed-role/"+c.Username)
	}
	return arn.Build("iam", "", c.AccountID, "user/"+c.Username)
}

type awsCallerCtxKey struct{}

func withAWSCaller(ctx context.Context, c awsCaller) context.Context {
	ctx = context.WithValue(ctx, awsCallerCtxKey{}, c)
	return withCallerAccount(ctx, c.AccountID)
}

func awsCallerFromContext(ctx context.Context) (awsCaller, bool) {
	c, ok := ctx.Value(awsCallerCtxKey{}).(awsCaller)
	return c, ok
}

// stsSessionResolver is implemented by stores that persist STS sessions.
type stsSessionResolver interface {
	getSTSSessionSecret(ctx context.Context, keyID string) (accountID, secret, sessionToken string, expiresAt time.Time, err error)
}

var errAWSUnsigned = errors.New("request is not signed")

// verifyAWSRequest authenticates a SigV4-signed request and returns the
// caller. bodyHash is the lowercase hex SHA-256 of the request body.
func (s *server) verifyAWSRequest(r *http.Request, bodyHash string) (awsCaller, error) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		return awsCaller{}, errAWSUnsigned
	}
	comp, err := sigv4.ParseAuthorizationHeader(auth)
	if err != nil {
		return awsCaller{}, err
	}
	if err := sigv4.CheckAmzDate(r.Header.Get("X-Amz-Date"), comp.Date, time.Now().UTC()); err != nil {
		return awsCaller{}, err
	}

	var (
		caller awsCaller
		secret string
	)
	switch {
	case s.cfg.expectedAccessKey != "" && s.cfg.secretAccessKey != "" &&
		subtle.ConstantTimeCompare([]byte(comp.AccessKey), []byte(s.cfg.expectedAccessKey)) == 1:
		// The statically configured deployment credential (KMS_ACCESS_KEY_ID /
		// KMS_SECRET_ACCESS_KEY) acts in the deployment account.
		_, acct := s.store.DeploymentIdentity()
		caller = awsCaller{AccessKeyID: comp.AccessKey, Username: comp.AccessKey, AccountID: acct}
		secret = s.cfg.secretAccessKey
	case isTempAccessKeyID(comp.AccessKey):
		resolver, ok := s.store.(stsSessionResolver)
		if !ok {
			return awsCaller{}, errors.New("temporary credentials are not supported by this store")
		}
		acct, sec, token, _, err := resolver.getSTSSessionSecret(r.Context(), comp.AccessKey)
		if err != nil {
			return awsCaller{}, err
		}
		// Temporary credentials are only valid together with their session
		// token; the secret alone must not be enough.
		presented := strings.TrimSpace(r.Header.Get("X-Amz-Security-Token"))
		if presented == "" || subtle.ConstantTimeCompare([]byte(presented), []byte(token)) != 1 {
			return awsCaller{}, errors.New("missing or invalid security token")
		}
		caller = awsCaller{AccessKeyID: comp.AccessKey, Username: comp.AccessKey, AccountID: acct, Temporary: true}
		secret = sec
	default:
		username, acct, sec, status, err := s.store.GetAccessKeyByID(r.Context(), comp.AccessKey)
		if err != nil {
			return awsCaller{}, err
		}
		if !strings.EqualFold(status, "active") {
			return awsCaller{}, errors.New("access key is not active")
		}
		caller = awsCaller{AccessKeyID: comp.AccessKey, Username: username, AccountID: acct}
		secret = sec
	}

	if err := sigv4.VerifySignature(r, bodyHash, secret); err != nil {
		return awsCaller{}, err
	}
	if !caller.Temporary && caller.AccessKeyID != s.cfg.expectedAccessKey {
		if err := s.store.TouchAccessKeyLastUsed(r.Context(), caller.AccessKeyID); err != nil {
			log.Printf("failed to update key last_used_at: %v", err)
		}
	}
	return caller, nil
}

// authenticateAWSJSON authenticates an AWS JSON-protocol request. On success
// it returns the request with the caller attached to its context. On failure
// it has already written the AWS-style error response.
func (s *server) authenticateAWSJSON(w http.ResponseWriter, r *http.Request) (*http.Request, bool) {
	if s.cfg.insecureDev {
		return r, true
	}
	bodyHash, err := sigv4.DrainAndHashBody(r, 1<<20)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidSignatureException", "request signature is invalid")
		return nil, false
	}
	caller, err := s.verifyAWSRequest(r, bodyHash)
	if err != nil {
		if errors.Is(err, errAWSUnsigned) {
			writeAWSJSONError(w, http.StatusForbidden, "MissingAuthenticationTokenException", "request is missing authentication token")
			return nil, false
		}
		log.Printf("sigv4 verification failed: %v", err)
		writeAWSJSONError(w, http.StatusForbidden, "UnrecognizedClientException", "the security token included in the request is invalid")
		return nil, false
	}
	return r.WithContext(withAWSCaller(r.Context(), caller)), true
}
