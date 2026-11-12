package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// Change requests (approval workflow).
//
// A change request is one proposed value for one item, held until enough
// distinct approvers sign off. The proposed value is sealed under the account's
// default KMS key before it is stored (store.ChangeRequestRecord), so it is
// never persisted in plaintext; only the explicit, editor-only, audited values
// endpoint decrypts it for review, and approval decrypts it to apply.
//
// Rules enforced here, server-side:
//   - the requester can never approve their own request (whatever their role);
//   - an approver needs a role at or above one of the policy's approverRoles
//     (default "admin"), so editors approve only where the policy allows it;
//   - approvalsRequired N needs N distinct approvers; each approval is
//     recorded with its comment, and the request applies on the Nth;
//   - approving and rejecting are atomic state transitions, so concurrent
//     decisions cannot both win or apply a value twice.
//
// Requests in an environment without a policy need one admin approval.

const (
	maxChangeRequestValueBytes = 65536 // the Secrets Manager value limit
	maxChangeRequestTitle      = 200
	maxChangeRequestComment    = 2000
)

// defaultApprovalPolicy applies to requests in an environment whose policy was
// removed (or never existed).
func defaultApprovalPolicy(project, env string) store.ApprovalPolicy {
	return store.ApprovalPolicy{Project: project, Env: env, ApprovalsRequired: 1, ApproverRoles: []string{"admin"}}
}

func (s *Server) policyForRequest(ctx context.Context, cr store.ChangeRequestRecord) (store.ApprovalPolicy, error) {
	p, ok, err := s.approvalPolicyFor(ctx, cr.Project, cr.Env)
	if err != nil {
		return store.ApprovalPolicy{}, err
	}
	if !ok {
		return defaultApprovalPolicy(cr.Project, cr.Env), nil
	}
	return p, nil
}

// approverRoleAllowed reports whether role meets any of the policy's roles.
func approverRoleAllowed(role string, roles []string) bool {
	for _, r := range roles {
		if uiRoleAtLeast(role, r) {
			return true
		}
	}
	return false
}

// approvalBlocker explains why sess may not approve cr, or "" when it may.
func approvalBlocker(sess *uiSession, cr store.ChangeRequestRecord, p store.ApprovalPolicy) string {
	switch {
	case cr.Status != store.ChangeRequestPending:
		return "This request has already been " + cr.Status + "."
	case sess == nil:
		return "Sign in to approve."
	case sess.ViaToken:
		// Approvals are a human control. Access keys may propose changes
		// (CI does), but approving takes a person signed in to the console.
		return "Approvals must be made by a person signed in to the console, not with an access key."
	case sess.Principal() == cr.Requester:
		return "You can't approve your own change request."
	case !approverRoleAllowed(sess.Role, p.ApproverRoles):
		return "Approving requires the " + strings.Join(p.ApproverRoles, " or ") + " role."
	}
	for _, a := range cr.Approvals {
		if a.Username == sess.Principal() {
			return "You have already approved this request."
		}
	}
	return ""
}

func crCoord(cr store.ChangeRequestRecord) (itemCoord, error) {
	return coordFromParts(cr.Project, cr.Env, cr.Path, cr.Key)
}

// sealProposedValue encrypts a proposed value under the account default key.
func (s *Server) sealProposedValue(ctx context.Context, value string) (cipherB64, keyID string, err error) {
	keyID, cipherB64, _, err = store.BuildSecretCiphertext(ctx, s.store.ResolveByID, s.store.ResolveDefault, "", value, "")
	return cipherB64, keyID, err
}

func (s *Server) openProposedValue(ctx context.Context, cr store.ChangeRequestRecord) (string, error) {
	return s.decryptParameterValue(ctx, cr.ProposedKMSKeyID, cr.ProposedCiphertext)
}

func changeRequestSummaryJSON(cr store.ChangeRequestRecord) map[string]any {
	out := map[string]any{
		"id":        cr.ID,
		"project":   cr.Project,
		"env":       cr.Env,
		"path":      cr.Path,
		"key":       cr.Key,
		"requester": cr.Requester,
		"status":    cr.Status,
		"createdAt": cr.CreatedAt.UTC().Format(time.RFC3339),
	}
	if cr.Title != "" {
		out["title"] = cr.Title
	}
	if cr.DecidedBy != "" && cr.DecidedAt != nil {
		out["decidedBy"] = cr.DecidedBy
		out["decidedAt"] = cr.DecidedAt.UTC().Format(time.RFC3339)
	}
	return out
}

type nativeChangeRequestBody struct {
	Project  string `json:"project"`
	Env      string `json:"env"`
	Path     string `json:"path"`
	Key      string `json:"key"`
	Value    string `json:"value"`
	KMSKeyID string `json:"kmsKeyId"`
	Title    string `json:"title"`
	Comment  string `json:"comment"`
	ID       string `json:"id"`
}

// handleV1CreateChangeRequest records a proposed write awaiting approval.
func (s *Server) handleV1CreateChangeRequest(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeChangeRequestBody
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "request body must be a JSON object")
		return
	}
	coord, err := coordFromParts(req.Project, req.Env, req.Path, req.Key)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	title, comment := strings.TrimSpace(req.Title), strings.TrimSpace(req.Comment)
	switch {
	case len(req.Value) > maxChangeRequestValueBytes:
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "value is larger than 65536 bytes")
		return
	case len(title) > maxChangeRequestTitle:
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "title is longer than 200 characters")
		return
	case len(comment) > maxChangeRequestComment:
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "comment is longer than 2000 characters")
		return
	}
	cr, err := s.newChangeRequest(ctx, sess, coord, req.Value, req.KMSKeyID, title, comment)
	if err != nil {
		log.Printf("change request: create: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "create_failed", "could not create the change request")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.CreateChangeRequest", KeyID: cr.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, changeRequestSummaryJSON(cr))
}

// newChangeRequest seals value and stores a pending request for coord.
func (s *Server) newChangeRequest(ctx context.Context, sess *uiSession, coord itemCoord, value, kmsKeyID, title, comment string) (store.ChangeRequestRecord, error) {
	cipherB64, keyID, err := s.sealProposedValue(ctx, value)
	if err != nil {
		return store.ChangeRequestRecord{}, err
	}
	base := ""
	if meta, err := s.store.DescribeSecret(ctx, coord.backingName()); err == nil {
		base = meta.CurrentVersionID
	}
	return s.store.CreateChangeRequest(ctx, store.ChangeRequestRecord{
		ID:                 "cr-" + cryptoutil.RandomHex(6),
		Project:            coord.Project,
		Env:                coord.Env,
		Path:               store.FolderPath(coord.Folder),
		Key:                coord.Key,
		Requester:          sess.Principal(),
		RequesterRole:      store.NormalizeUIRole(sess.Role),
		Title:              title,
		Comment:            comment,
		ProposedCiphertext: cipherB64,
		ProposedKMSKeyID:   keyID,
		ProposedLength:     utf8.RuneCountInString(value),
		TargetKMSKeyID:     strings.TrimSpace(kmsKeyID),
		BaseVersionID:      base,
	})
}

// handleV1ListChangeRequests lists the caller account's change requests.
func (s *Server) handleV1ListChangeRequests(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "viewer")
	if !ok {
		return
	}
	requests, err := s.store.ListChangeRequests(ctx)
	if err != nil {
		log.Printf("change request: list: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "list_failed", "could not list change requests")
		return
	}
	out := make([]map[string]any, 0, len(requests))
	for _, cr := range requests {
		out = append(out, changeRequestSummaryJSON(cr))
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"changeRequests": out})
}

// versionOrdinals maps each version ID of a secret to its 1-based ordinal
// (oldest = 1) and reports how many versions there are.
func (s *Server) versionOrdinals(ctx context.Context, name string) (map[string]int, int) {
	entries, err := s.store.ListSecretVersionIDs(ctx, name)
	if err != nil {
		return map[string]int{}, 0
	}
	out := make(map[string]int, len(entries))
	for i, e := range entries {
		out[e.VersionID] = i + 1
	}
	return out, len(entries)
}

// handleV1ChangeRequestDetail returns a request with fingerprints (keyed, see
// valueFingerprint) and lengths of the previous and proposed values, the
// applicable policy, the approvals so far, and whether the caller may approve.
func (s *Server) handleV1ChangeRequestDetail(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.secretsSession(w, r, "viewer")
	if !ok {
		return
	}
	cr, ok := s.loadChangeRequest(w, ctx, r.URL.Query().Get("id"))
	if !ok {
		return
	}
	policy, err := s.policyForRequest(ctx, cr)
	if err != nil {
		log.Printf("change request: policy: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not read the approval policy")
		return
	}
	out := changeRequestSummaryJSON(cr)
	if cr.Comment != "" {
		out["comment"] = cr.Comment
	}
	if cr.RequesterRole != "" {
		out["requesterRole"] = cr.RequesterRole
	}
	if name := s.displayNameOf(ctx, cr.Requester); name != "" {
		out["requesterDisplayName"] = name
	}
	if cr.DecisionComment != "" {
		out["decisionComment"] = cr.DecisionComment
	}

	change := map[string]any{"key": cr.Key, "path": cr.Path, "change": "added"}
	if coord, err := crCoord(cr); err == nil {
		ordinals, total := s.versionOrdinals(ctx, coord.backingName())
		if prev, ok := s.previousValue(ctx, coord, cr); ok {
			change["change"] = "modified"
			fp := map[string]any{"sha256": s.valueFingerprint(*prev.SecretString), "length": utf8.RuneCountInString(*prev.SecretString)}
			if n := ordinals[prev.VersionID]; n > 0 {
				fp["version"] = "v" + strconv.Itoa(n)
			}
			change["previous"] = fp
		}
		if proposed, err := s.openProposedValue(ctx, cr); err == nil {
			fp := map[string]any{"sha256": s.valueFingerprint(proposed), "length": cr.ProposedLength}
			if cr.Status == store.ChangeRequestPending {
				fp["version"] = "v" + strconv.Itoa(total+1)
			}
			change["proposed"] = fp
		} else {
			log.Printf("change request %s: open proposed value: %v", cr.ID, err)
		}
	}
	out["changes"] = []map[string]any{change}
	out["policy"] = map[string]any{
		"name":              cr.Project + "/" + cr.Env + " approval",
		"approvalsRequired": policy.ApprovalsRequired,
		"approverRoles":     policy.ApproverRoles,
	}
	approvals := make([]map[string]any, 0, len(cr.Approvals))
	for _, a := range cr.Approvals {
		item := map[string]any{"username": a.Username, "decidedAt": a.DecidedAt.UTC().Format(time.RFC3339)}
		if a.Comment != "" {
			item["comment"] = a.Comment
		}
		approvals = append(approvals, item)
	}
	out["approvals"] = approvals
	reason := approvalBlocker(sess, cr, policy)
	out["canApprove"] = reason == ""
	if reason != "" {
		out["cannotApproveReason"] = reason
	}
	writeNativeJSON(w, http.StatusOK, out)
}

// previousValue is the value a request replaces: the item's current value
// while the request is pending, and the version it was based on once decided
// (none when the request created the item).
func (s *Server) previousValue(ctx context.Context, coord itemCoord, cr store.ChangeRequestRecord) (store.SecretValueRecord, bool) {
	version := ""
	if cr.Status != store.ChangeRequestPending {
		if cr.BaseVersionID == "" {
			return store.SecretValueRecord{}, false
		}
		version = cr.BaseVersionID
	}
	prev, err := s.secretsSvc().RevealItem(ctx, coord, version, "")
	if err != nil || prev.SecretString == nil {
		return store.SecretValueRecord{}, false
	}
	return prev, true
}

// displayNameOf returns a console user's display name, if known.
func (s *Server) displayNameOf(ctx context.Context, username string) string {
	if u, ok := s.lookupUser(ctx, username); ok {
		return u.DisplayName
	}
	return ""
}

func (s *Server) loadChangeRequest(w http.ResponseWriter, ctx context.Context, id string) (store.ChangeRequestRecord, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return store.ChangeRequestRecord{}, false
	}
	cr, err := s.store.GetChangeRequest(ctx, id)
	if errors.Is(err, store.ErrChangeRequestNotFound) {
		writeNativeError(w, http.StatusNotFound, "not_found", "change request not found")
		return store.ChangeRequestRecord{}, false
	}
	if err != nil {
		log.Printf("change request: get: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not read the change request")
		return store.ChangeRequestRecord{}, false
	}
	return cr, true
}

// handleV1ChangeRequestValues reveals the previous and proposed values of a
// request to an editor, for review. Audited.
func (s *Server) handleV1ChangeRequestValues(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	cr, ok := s.loadChangeRequest(w, ctx, r.URL.Query().Get("id"))
	if !ok {
		return
	}
	item := map[string]any{"key": cr.Key}
	proposed, err := s.openProposedValue(ctx, cr)
	if err != nil {
		log.Printf("change request %s: open proposed value: %v", cr.ID, err)
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RevealChangeRequest", KeyID: cr.ID, Result: "error", ErrorType: "DecryptFailed", AuditOrigin: s.auditOrigin(r)})
		writeNativeError(w, http.StatusInternalServerError, "decrypt_failed", "could not decrypt the proposed value")
		return
	}
	item["proposedValue"] = proposed
	if coord, err := crCoord(cr); err == nil {
		if prev, ok := s.previousValue(ctx, coord, cr); ok {
			item["previousValue"] = *prev.SecretString
		}
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RevealChangeRequest", KeyID: cr.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"changes": []map[string]any{item}})
}

// handleV1ApproveChangeRequest records the caller's approval and applies the
// request once it has the required number of distinct approvals.
func (s *Server) handleV1ApproveChangeRequest(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeChangeRequestBody
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "request body must be a JSON object")
		return
	}
	comment := strings.TrimSpace(req.Comment)
	if len(comment) > maxChangeRequestComment {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "comment is longer than 2000 characters")
		return
	}
	cr, ok := s.loadChangeRequest(w, ctx, req.ID)
	if !ok {
		return
	}
	policy, err := s.policyForRequest(ctx, cr)
	if err != nil {
		log.Printf("change request: policy: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not read the approval policy")
		return
	}
	if reason := approvalBlocker(sess, cr, policy); reason != "" {
		status, code := http.StatusForbidden, "forbidden"
		if cr.Status != store.ChangeRequestPending {
			status, code = http.StatusConflict, "already_decided"
		}
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.ApproveChangeRequest", KeyID: cr.ID, Result: "denied", ErrorType: code, AuditOrigin: s.auditOrigin(r)})
		writeNativeError(w, status, code, reason)
		return
	}
	cr, err = s.store.AddChangeRequestApproval(ctx, cr.ID, store.ChangeRequestApproval{Username: sess.Principal(), Comment: comment})
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.ApproveChangeRequest", KeyID: cr.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	resp := map[string]any{"id": cr.ID, "approvals": len(cr.Approvals), "approvalsRequired": policy.ApprovalsRequired}
	if len(cr.Approvals) < policy.ApprovalsRequired {
		resp["approved"], resp["applied"], resp["status"] = false, false, cr.Status
		writeNativeJSON(w, http.StatusOK, resp)
		return
	}
	// Enough approvals: claim the request (only one approver can), then apply.
	decided, err := s.store.TransitionChangeRequest(ctx, cr.ID, store.ChangeRequestPending, store.ChangeRequestApproved, sess.Principal(), comment)
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	if err := s.applyChangeRequest(ctx, decided); err != nil {
		log.Printf("change request %s: apply: %v", cr.ID, err)
		if _, rerr := s.store.TransitionChangeRequest(ctx, cr.ID, store.ChangeRequestApproved, store.ChangeRequestPending, "", ""); rerr != nil {
			log.Printf("change request %s: reopen after failed apply: %v", cr.ID, rerr)
		}
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.ApplyChangeRequest", KeyID: cr.ID, Result: "error", ErrorType: "ApplyFailed", AuditOrigin: s.auditOrigin(r)})
		writeNativeError(w, http.StatusInternalServerError, "apply_failed", "approved, but the value could not be written; the request is pending again")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.ApplyChangeRequest", KeyID: cr.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	resp["approved"], resp["applied"], resp["status"] = true, true, decided.Status
	writeNativeJSON(w, http.StatusOK, resp)
}

// applyChangeRequest writes the approved value. The version is attributed to
// the requester, whose change it is.
func (s *Server) applyChangeRequest(ctx context.Context, cr store.ChangeRequestRecord) error {
	coord, err := crCoord(cr)
	if err != nil {
		return err
	}
	value, err := s.openProposedValue(ctx, cr)
	if err != nil {
		return err
	}
	_, err = s.secretsSvc().PutItem(store.WithActor(ctx, cr.Requester), coord, value, cr.TargetKMSKeyID)
	return err
}

// handleV1RejectChangeRequest rejects a pending request. Approvers (per the
// policy) may reject; the requester may withdraw their own request.
func (s *Server) handleV1RejectChangeRequest(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeChangeRequestBody
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "request body must be a JSON object")
		return
	}
	comment := strings.TrimSpace(req.Comment)
	if len(comment) > maxChangeRequestComment {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "comment is longer than 2000 characters")
		return
	}
	cr, ok := s.loadChangeRequest(w, ctx, req.ID)
	if !ok {
		return
	}
	policy, err := s.policyForRequest(ctx, cr)
	if err != nil {
		log.Printf("change request: policy: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not read the approval policy")
		return
	}
	if sess.Principal() != cr.Requester && !approverRoleAllowed(sess.Role, policy.ApproverRoles) {
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RejectChangeRequest", KeyID: cr.ID, Result: "denied", ErrorType: "forbidden", AuditOrigin: s.auditOrigin(r)})
		writeNativeError(w, http.StatusForbidden, "forbidden", "Rejecting requires the "+strings.Join(policy.ApproverRoles, " or ")+" role.")
		return
	}
	if _, err := s.store.TransitionChangeRequest(ctx, cr.ID, store.ChangeRequestPending, store.ChangeRequestRejected, sess.Principal(), comment); err != nil {
		writeDecisionError(w, err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RejectChangeRequest", KeyID: cr.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"rejected": true, "id": cr.ID})
}

func writeDecisionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrChangeRequestNotFound):
		writeNativeError(w, http.StatusNotFound, "not_found", "change request not found")
	case errors.Is(err, store.ErrChangeRequestDecided):
		writeNativeError(w, http.StatusConflict, "already_decided", "this request has already been decided")
	case errors.Is(err, store.ErrAlreadyApproved):
		writeNativeError(w, http.StatusConflict, "already_approved", "you have already approved this request")
	default:
		log.Printf("change request decision: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not record the decision")
	}
}

// ---- approval policies --------------------------------------------------------

// handleV1ListApprovalPolicies returns the account's approval policies.
func (s *Server) handleV1ListApprovalPolicies(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "viewer")
	if !ok {
		return
	}
	policies, err := s.store.ListApprovalPolicies(ctx)
	if err != nil {
		log.Printf("approval policies: list: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "list_failed", "could not list approval policies")
		return
	}
	out := make([]map[string]any, 0, len(policies))
	explicit := map[string]bool{}
	for _, p := range policies {
		roles := p.ApproverRoles
		if len(roles) == 0 {
			roles = []string{"admin"}
		}
		explicit[p.Project+"/"+p.Env] = true
		out = append(out, map[string]any{"project": p.Project, "env": p.Env, "approvalsRequired": p.ApprovalsRequired, "approverRoles": roles, "source": "project"})
	}
	// Environments covered only by the organization's approvalEnvironments
	// default, listed per existing project so the console routes them through
	// change requests too.
	if len(s.orgSettings(ctx).ApprovalEnvironments) > 0 {
		if projects, err := s.secretsSvc().ListProjects(ctx); err == nil {
			for _, pr := range projects {
				for _, env := range pr.Environments {
					if explicit[pr.Slug+"/"+env] {
						continue
					}
					if p, ok, _ := s.orgDefaultPolicy(ctx, pr.Slug, env); ok {
						out = append(out, map[string]any{"project": p.Project, "env": p.Env, "approvalsRequired": p.ApprovalsRequired, "approverRoles": p.ApproverRoles, "source": "organization"})
					}
				}
			}
		}
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"policies": out})
}

type nativeApprovalPolicyRequest struct {
	Project           string   `json:"project"`
	Env               string   `json:"env"`
	ApprovalsRequired int      `json:"approvalsRequired"`
	ApproverRoles     []string `json:"approverRoles"`
}

// handleV1PutApprovalPolicy creates, replaces or (approvalsRequired 0)
// removes an environment's approval policy. Admin only.
func (s *Server) handleV1PutApprovalPolicy(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.secretsSession(w, r, "admin")
	if !ok {
		return
	}
	var req nativeApprovalPolicyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "request body must be a JSON object")
		return
	}
	project, env := strings.TrimSpace(req.Project), strings.TrimSpace(req.Env)
	if err := validateSegment("project", project); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := validateSegment("env", env); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.ApprovalsRequired < 0 || req.ApprovalsRequired > 10 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "approvalsRequired must be between 0 and 10")
		return
	}
	roles := []string{}
	for _, role := range req.ApproverRoles {
		role = strings.ToLower(strings.TrimSpace(role))
		if role != "admin" && role != "editor" {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", "approverRoles may contain only admin and editor")
			return
		}
		if !store.ContainsString(roles, role) {
			roles = append(roles, role)
		}
	}
	if len(roles) == 0 {
		roles = []string{"admin"}
	}
	if err := s.store.PutApprovalPolicy(ctx, store.ApprovalPolicy{Project: project, Env: env, ApprovalsRequired: req.ApprovalsRequired, ApproverRoles: roles, UpdatedBy: sess.Principal()}); err != nil {
		log.Printf("approval policies: put: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "save_failed", "could not save the approval policy")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.PutApprovalPolicy", KeyID: project + "/" + env, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"saved": true})
}
