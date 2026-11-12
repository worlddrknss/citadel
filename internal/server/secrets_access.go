package server

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// Access rules shared by the secrets, parameters and change-request handlers:
// who may read values, which environments require approval, and value
// fingerprints.
//
// Revealing values. Whether the viewer role may read secret values is a
// per-account setting (GET/POST /v1/secrets/settings, viewersCanReveal) that
// defaults to false: out of the box only editors and admins can reveal a
// secret, read an old version's value, export .env (the console exports by
// revealing each value), or read a SecureString parameter. Viewers keep
// metadata (names, versions, lengths, keyed fingerprints). Writes and bulk
// operations already require editor. The AWS-compatible API is governed by
// resource policies, not console roles, and is unaffected.
//
// Approval. An environment with an approval policy (store.ApprovalPolicy)
// refuses direct value writes: the native API answers 409 approval_required
// and the AWS API AccessDeniedException. Writes go through change requests.

// secretsSession is nativeSession plus the actor on the context, so the store
// records who wrote each version.
func (s *Server) secretsSession(w http.ResponseWriter, r *http.Request, minRole string) (*uiSession, context.Context, bool) {
	sess, ctx, ok := s.nativeSession(w, r, minRole)
	if !ok {
		return nil, nil, false
	}
	return sess, store.WithActor(ctx, sess.Username), true
}

// canRevealValues reports whether sess may read secret values in its account.
func (s *Server) canRevealValues(ctx context.Context, sess *uiSession) (bool, error) {
	if sess == nil {
		return false, nil
	}
	if uiRoleAtLeast(sess.Role, "editor") {
		return true, nil
	}
	settings, err := s.store.GetSecretSettings(ctx)
	if err != nil {
		return false, err
	}
	return settings.ViewersCanReveal, nil
}

// requireReveal writes the refusal and returns false when sess may not read
// values. The refusal is audited.
func (s *Server) requireReveal(w http.ResponseWriter, r *http.Request, ctx context.Context, sess *uiSession, action string) bool {
	ok, err := s.canRevealValues(ctx, sess)
	if err != nil {
		log.Printf("secret settings read failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not check reveal permission")
		return false
	}
	if !ok {
		s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "denied", ErrorType: "RevealForbidden", AuditOrigin: s.auditOrigin(r)})
		writeNativeError(w, http.StatusForbidden, "reveal_forbidden", "viewers cannot reveal secret values in this account")
		return false
	}
	return true
}

// approvalPolicyFor returns the policy for project/env, if any. A per-project
// policy (store.ApprovalStore) wins; otherwise the organization settings'
// approvalEnvironments (environment slugs, any project) and
// approvalMinApprovers act as the default, approved by admins.
func (s *Server) approvalPolicyFor(ctx context.Context, project, env string) (store.ApprovalPolicy, bool, error) {
	p, ok, err := s.store.GetApprovalPolicy(ctx, project, env)
	if err != nil {
		return store.ApprovalPolicy{}, false, err
	}
	if !ok || p.ApprovalsRequired <= 0 {
		return s.orgDefaultPolicy(ctx, project, env)
	}
	if len(p.ApproverRoles) == 0 {
		p.ApproverRoles = []string{"admin"}
	}
	return p, true, nil
}

// requireNoApproval refuses (409 approval_required) a direct write into an
// environment that requires approval and returns false; it returns true when
// the write may proceed.
func (s *Server) requireNoApproval(w http.ResponseWriter, r *http.Request, ctx context.Context, project, env, action string) bool {
	_, required, err := s.approvalPolicyFor(ctx, project, env)
	if err != nil {
		log.Printf("approval policy read failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not check approval policy")
		return false
	}
	if required {
		s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "denied", ErrorType: "ApprovalRequired", AuditOrigin: s.auditOrigin(r)})
		writeNativeError(w, http.StatusConflict, "approval_required", "changes to "+project+"/"+env+" require approval; submit a change request")
		return false
	}
	return true
}

// awsWriteNeedsApproval reports whether a write to the backing secret name
// falls in an approval-required environment. Names outside the
// project/env/... shape are never gated. A policy-read failure fails closed.
func (s *Server) awsWriteNeedsApproval(ctx context.Context, name string) bool {
	pi, ok := parseSecretName(strings.TrimSpace(name))
	if !ok {
		return false
	}
	_, required, err := s.approvalPolicyFor(ctx, pi.Project, pi.Env)
	if err != nil {
		log.Printf("approval policy read failed: %v", err)
		return true
	}
	return required
}

// awsApprovalRequiredMessage accompanies the AccessDeniedException returned to
// AWS clients writing into an approval-required environment.
const awsApprovalRequiredMessage = "this secret is in an environment that requires approval; submit a change request in the Citadel console"

var (
	ephemeralFingerprintOnce sync.Once
	ephemeralFingerprintKey  []byte
)

// fingerprintKey is the per-deployment key for value fingerprints, derived
// with HKDF from the KMS wrapping key (or, for the in-memory store, the
// legacy master key). Without either it falls back to a random per-process
// key, so fingerprints are still keyed, just not stable across restarts.
func (s *Server) fingerprintKey() []byte {
	switch {
	case len(s.cfg.WrappingKey) > 0:
		return cryptoutil.DeriveFingerprintKey(s.cfg.WrappingKey)
	case len(s.cfg.LegacyMasterKey) > 0:
		return cryptoutil.DeriveFingerprintKey(s.cfg.LegacyMasterKey)
	}
	ephemeralFingerprintOnce.Do(func() {
		ephemeralFingerprintKey = cryptoutil.DeriveFingerprintKey([]byte(cryptoutil.RandomHex(32)))
	})
	return ephemeralFingerprintKey
}

// valueFingerprint is the keyed fingerprint of a value (see
// cryptoutil.ValueFingerprint), never a plain hash.
func (s *Server) valueFingerprint(value string) string {
	return cryptoutil.ValueFingerprint(s.fingerprintKey(), []byte(value))
}

// writeSecretsFailure reports a failed secrets operation. Validation and
// well-known domain errors keep their message (they describe the caller's
// input); anything else is logged and replaced by a stable message so storage
// or crypto internals never reach the client.
func writeSecretsFailure(w http.ResponseWriter, status int, code string, err error) {
	switch {
	case errors.Is(err, errItemNotFound), errors.Is(err, sql.ErrNoRows):
		writeNativeError(w, http.StatusNotFound, "not_found", "item not found")
		return
	case errors.Is(err, store.ErrSecretExists):
		writeNativeError(w, http.StatusConflict, "already_exists", "an item with that name already exists")
		return
	case errors.Is(err, errContainerNotEmpty), errors.Is(err, errNoHierarchyStore),
		errors.Is(err, store.ErrSecretPendingDeletion), errors.Is(err, store.ErrInvalidSecretVersion):
		writeNativeError(w, status, code, err.Error())
		return
	}
	msg := err.Error()
	for _, safe := range []string{"must match", "is required", "invalid folder segment", "RecoveryWindowInDays", "cannot re-key", "at least one tag", "AutomaticallyAfterDays", "scheduled for deletion", "must be base64", "names a folder"} {
		if strings.Contains(msg, safe) {
			writeNativeError(w, status, code, msg)
			return
		}
	}
	log.Printf("%s: %v", code, err)
	writeNativeError(w, http.StatusInternalServerError, code, "the operation failed")
}

// orgDefaultPolicy is the policy implied by the organization settings for
// project/env when no per-project policy exists. The settings' self-approval
// flag is deliberately ignored: a requester never approves their own request.
func (s *Server) orgDefaultPolicy(ctx context.Context, project, env string) (store.ApprovalPolicy, bool, error) {
	org := s.orgSettings(ctx)
	for _, e := range org.ApprovalEnvironments {
		if strings.EqualFold(strings.TrimSpace(e), env) {
			return store.ApprovalPolicy{
				Project:           project,
				Env:               env,
				ApprovalsRequired: max(org.ApprovalMinApprovers, 1),
				ApproverRoles:     []string{"admin"},
			}, true, nil
		}
	}
	return store.ApprovalPolicy{}, false, nil
}
