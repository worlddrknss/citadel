package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// Native Citadel API (/v1)
//
// This is the first-class, protocol-clean JSON API that the Svelte control
// plane and native SDKs talk to. It deliberately does NOT speak the AWS
// X-Amz-Target dialect; instead it exposes an Infisical-style hierarchy:
//
//	Account (org)  ->  Project  ->  Environment  ->  Folder  ->  Item (KEY=value)
//
// The hierarchy is *projected* onto the existing AWS-compatible secrets store:
// each native item is persisted as a Secrets Manager secret whose name encodes
// its full path:
//
//	<project>/<env>[/<folder-segments...>]/<KEY>
//
// Because the backing records are ordinary AWS Secrets Manager secrets, the
// same data remains readable through the AWS facade (and therefore through
// External Secrets Operator / the AWS SDK) with zero extra work — this is the
// "both projection shapes" promise from PLAN.md realised for free.

// nativeSegmentRe constrains every path segment (project, environment, folder
// segment, and key) to a safe, unambiguous character set so that the "/"
// separator used to encode the hierarchy can never be confused with data.
var nativeSegmentRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// resolveNativeSession resolves the caller's console session for the native API.
// It returns a JSON 401/403 so the SPA can react programmatically, and a
// context scoped to the session's account so the store applies per-account
// isolation via the existing accountFilter plumbing.
func (s *Server) resolveNativeSession(w http.ResponseWriter, r *http.Request, minRole string) (*uiSession, context.Context, bool) {
	// Bearer token auth (machine identities) takes precedence over cookies so
	// native SDKs and CI can talk to /v1 without a browser session.
	if sess, ctx, ok, handled := s.nativeTokenSession(w, r, minRole); handled {
		return sess, ctx, ok
	}
	token := s.sessionToken(r)
	if token == "" {
		// No console users at all: only insecure dev mode gets the implicit
		// local admin. Startup refuses this state otherwise (or runs in
		// bootstrap mode, where the API is closed); this is the backstop.
		if s.cfg.InsecureDev && !s.hasConsoleUsers(r.Context()) {
			sess := &uiSession{Username: "local", Role: "admin", DisplayName: "Local Admin", PlatformAdmin: true}
			return sess, r.Context(), true
		}
		writeNativeError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return nil, nil, false
	}
	session, err := s.resolveSession(r.Context(), token)
	if err != nil {
		s.clearSessionCookie(w)
		writeNativeError(w, http.StatusUnauthorized, "unauthorized", "session expired")
		return nil, nil, false
	}
	if session.Method == store.SessionMethodMFAEnrollment && !mfaEnrollmentAllowed(r) {
		// Restricted session: the organization requires MFA and this user
		// has not enrolled yet.
		writeNativeError(w, http.StatusForbidden, "mfa_enrollment_required", "set up multi-factor authentication to continue")
		return nil, nil, false
	}
	if !uiRoleAtLeast(session.Role, minRole) {
		writeNativeError(w, http.StatusForbidden, "forbidden", "insufficient role")
		return nil, nil, false
	}
	// Scope the request context to the session's current account so the store's
	// AccountFilter/accountForContext helpers isolate reads and stamp writes.
	ctx := store.WithCallerAccount(r.Context(), strings.TrimSpace(session.AccountID))
	return session, ctx, true
}

// nativeTokenSession authenticates a machine identity from an Authorization:
// Bearer "<accessKeyId>:<secret>" header. It returns handled=false when no
// bearer token is present (so the caller falls back to cookie auth). When a
// token is present it is fully resolved here: ok reports success, and the
// request context is scoped to the token's account for per-tenant isolation.
func (s *Server) nativeTokenSession(w http.ResponseWriter, r *http.Request, minRole string) (sess *uiSession, ctx context.Context, ok bool, handled bool) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return nil, nil, false, false
	}
	token := strings.TrimSpace(auth[len("Bearer "):])
	keyID, secret, found := strings.Cut(token, ":")
	keyID = strings.TrimSpace(keyID)
	if !found || keyID == "" || secret == "" {
		// A token without the "<keyId>:<secret>" shape may be a native OIDC
		// (JWT) identity. That path is scaffolded for P9 but not yet wired to a
		// concrete issuer, so we surface a clear, stable error here.
		if sess, ctx, ok := s.verifyNativeOIDC(r, token); ok {
			return sess, ctx, true, true
		}
		writeNativeError(w, http.StatusUnauthorized, "unauthorized", "invalid bearer token format")
		return nil, nil, false, true
	}
	// STS temporary credentials are for the AWS APIs only, where their session
	// token is checked; they are never a /v1 bearer token.
	if store.IsTempAccessKeyID(keyID) {
		writeNativeError(w, http.StatusUnauthorized, "unauthorized", "invalid or inactive token")
		return nil, nil, false, true
	}
	owner, accountID, storedSecret, status, err := s.store.GetAccessKeyByID(r.Context(), keyID)
	if err != nil || strings.ToLower(status) != "active" {
		writeNativeError(w, http.StatusUnauthorized, "unauthorized", "invalid or inactive token")
		return nil, nil, false, true
	}
	if subtle.ConstantTimeCompare([]byte(secret), []byte(storedSecret)) != 1 {
		writeNativeError(w, http.StatusUnauthorized, "unauthorized", "invalid or inactive token")
		return nil, nil, false, true
	}
	// A token acts with its owner's role in the key's account, never more:
	// otherwise any viewer could mint a key and act as admin. A key whose
	// owner no longer exists, or no longer belongs to the account, grants
	// nothing. Tokens never carry platform-admin rights.
	ownerUser, ownerExists := s.lookupUser(r.Context(), owner)
	if !ownerExists {
		writeNativeError(w, http.StatusUnauthorized, "unauthorized", "invalid or inactive token")
		return nil, nil, false, true
	}
	tokenRole, member := accountRole(s.userMemberships(r.Context(), ownerUser), strings.TrimSpace(accountID))
	if !member {
		writeNativeError(w, http.StatusUnauthorized, "unauthorized", "invalid or inactive token")
		return nil, nil, false, true
	}
	if !uiRoleAtLeast(tokenRole, minRole) {
		writeNativeError(w, http.StatusForbidden, "forbidden", "insufficient role")
		return nil, nil, false, true
	}
	_ = s.store.TouchAccessKeyLastUsed(r.Context(), keyID)
	sess = &uiSession{Username: keyID, Role: tokenRole, AccountID: accountID, DisplayName: "Machine Identity", ViaToken: true, Owner: ownerUser.Username, Accounts: []string{accountID}}
	ctx = store.WithCallerAccount(r.Context(), strings.TrimSpace(accountID))
	return sess, ctx, true, true
}

// verifyNativeOIDC is the native OIDC identity extension point (PLAN.md §6 P9).
// When a future deployment configures an OIDC issuer/audience, this is where a
// JWT bearer would be validated and mapped to an account-scoped session. It is
// currently a no-op scaffold that reports ok=false so callers fall through to
// the existing access-key and cookie auth paths, leaving behaviour unchanged.
func (s *Server) verifyNativeOIDC(r *http.Request, token string) (*uiSession, context.Context, bool) {
	_ = r
	_ = token
	return nil, nil, false
}

// ---- JSON helpers ----------------------------------------------------------

func writeNativeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

type nativeErrorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeNativeError(w http.ResponseWriter, status int, code, msg string) {
	writeNativeJSON(w, status, nativeErrorBody{Error: code, Message: msg})
}

// ---- path <-> name projection ---------------------------------------------

// normalizeFolder turns a user-supplied folder path into a clean slice of
// segments. Root ("", "/", ".") yields an empty slice.
func normalizeFolder(folder string) ([]string, error) {
	folder = strings.TrimSpace(folder)
	folder = strings.Trim(folder, "/")
	if folder == "" || folder == "." {
		return nil, nil
	}
	segs := strings.Split(folder, "/")
	out := make([]string, 0, len(segs))
	for _, seg := range segs {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		if !nativeSegmentRe.MatchString(seg) {
			return nil, errors.New("invalid folder segment: " + seg)
		}
		out = append(out, seg)
	}
	return out, nil
}

// flatSecretName builds the backing AWS secret name for an item.
func flatSecretName(project, env string, folder []string, key string) string {
	parts := append([]string{project, env}, folder...)
	parts = append(parts, key)
	return strings.Join(parts, "/")
}

// parsedItem is the decomposition of a backing secret name into native coords.
type parsedItem struct {
	Project string
	Env     string
	Folder  []string
	Key     string
}

// parseSecretName decomposes a flat backing name into native coordinates. It
// reports ok=false for names that do not fit the project/env/.../key shape.
func parseSecretName(name string) (parsedItem, bool) {
	parts := strings.Split(name, "/")
	if len(parts) < 3 {
		return parsedItem{}, false
	}
	for _, p := range parts {
		if !nativeSegmentRe.MatchString(p) {
			return parsedItem{}, false
		}
	}
	return parsedItem{
		Project: parts[0],
		Env:     parts[1],
		Folder:  parts[2 : len(parts)-1],
		Key:     parts[len(parts)-1],
	}, true
}

func validateSegment(field, value string) error {
	if !nativeSegmentRe.MatchString(strings.TrimSpace(value)) {
		return errors.New(field + " must match [A-Za-z0-9_.-]+")
	}
	return nil
}

// ---- response models -------------------------------------------------------

type nativeMeResponse struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"displayName"`
	Role        string   `json:"role"`
	AccountID   string   `json:"accountId"`
	Accounts    []string `json:"accounts"`
}

type nativeProject struct {
	Slug         string   `json:"slug"`
	Environments []string `json:"environments"`
	// Name is the display name set via /v1/projects/rename, when set.
	Name string `json:"name,omitempty"`
	// EnvironmentCounts is the number of live secrets in each environment
	// (at any depth), keyed by environment slug.
	EnvironmentCounts map[string]int `json:"environmentCounts"`
}

type nativeItem struct {
	Project      string `json:"project"`
	Env          string `json:"env"`
	Path         string `json:"path"`
	Key          string `json:"key"`
	ARN          string `json:"arn"`
	UpdatedAt    string `json:"updatedAt"`
	DeletionDate string `json:"deletionDate,omitempty"`
	// Version is the number of stored versions, i.e. the ordinal of the
	// newest one.
	Version   int         `json:"version,omitempty"`
	UpdatedBy string      `json:"updatedBy,omitempty"`
	Tags      []nativeTag `json:"tags"`
	// RotationDue is set when a rotation schedule has come due (Citadel
	// records schedules but cannot run rotation functions).
	RotationDue bool `json:"rotationDue,omitempty"`
}

// ---- handlers --------------------------------------------------------------

func (s *Server) handleV1Me(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	writeNativeJSON(w, http.StatusOK, meResponse(sess))
}

// handleV1Projects returns the distinct projects (and their environments)
// visible to the caller's account, via the shared secrets service.
func (s *Server) handleV1Projects(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "viewer")
	if !ok {
		return
	}
	projects, err := s.secretsSvc().ListProjects(ctx)
	if err != nil {
		writeSecretsFailure(w, http.StatusInternalServerError, "list_failed", err)
		return
	}
	out := make([]nativeProject, 0, len(projects))
	for _, p := range projects {
		out = append(out, nativeProject{Slug: p.Slug, Environments: p.Environments, Name: p.Name, EnvironmentCounts: p.EnvCounts})
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"projects": out})
}

// handleV1ListSecrets lists the items at a given project/env/folder. Values are
// never included; callers must use the reveal endpoint for a single item.
func (s *Server) handleV1ListSecrets(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "viewer")
	if !ok {
		return
	}
	q := r.URL.Query()
	project := strings.TrimSpace(q.Get("project"))
	env := strings.TrimSpace(q.Get("env"))
	if project == "" || env == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "project and env are required")
		return
	}
	wantFolder, err := normalizeFolder(q.Get("path"))
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	listing, err := s.secretsSvc().listFolderDetailed(ctx, project, env, wantFolder)
	if err != nil {
		writeSecretsFailure(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	folders, found, shadowing := listing.Folders, listing.Items, listing.Shadowed
	toNative := func(it itemSummary) nativeItem {
		ni := nativeItem{
			Project:   it.Project,
			Env:       it.Env,
			Path:      it.Path,
			Key:       it.Key,
			ARN:       it.ARN,
			UpdatedAt: it.UpdatedAt.Format(time.RFC3339),
			Version:   it.Version,
			UpdatedBy: it.UpdatedBy,
			Tags:      make([]nativeTag, 0, len(it.Tags)),

			RotationDue: it.RotationDue,
		}
		for _, t := range it.Tags {
			ni.Tags = append(ni.Tags, nativeTag{Key: t.Key, Value: t.Value})
		}
		if it.DeletionDate != nil {
			ni.DeletionDate = it.DeletionDate.Format(time.RFC3339)
		}
		return ni
	}
	items := make([]nativeItem, 0, len(found))
	for _, it := range found {
		items = append(items, toNative(it))
	}
	// Reported apart from items so the UI can show it for what it is: an object
	// wearing this folder's name, shadowing the folder's JSON projection, and
	// until now invisible here.
	shadowed := make([]nativeItem, 0, len(shadowing))
	for _, it := range shadowing {
		shadowed = append(shadowed, toNative(it))
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{
		"project":      project,
		"env":          env,
		"path":         store.FolderPath(wantFolder),
		"folders":      folders,
		"items":        items,
		"shadowed":     shadowed,
		"folderCounts": listing.FolderCounts,
	})
}

// handleV1DeleteShadowing removes the object sitting at a folder's own name.
// Separate from handleV1DeleteSecret, which requires a key: this object has none,
// which is precisely why it could never be deleted from the console.
func (s *Server) handleV1DeleteShadowing(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	q := r.URL.Query()
	project := strings.TrimSpace(q.Get("project"))
	env := strings.TrimSpace(q.Get("env"))
	if project == "" || env == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "project and env are required")
		return
	}
	folder, err := normalizeFolder(q.Get("path"))
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	force := strings.EqualFold(strings.TrimSpace(q.Get("force")), "true")
	windowDays := 0
	if v := strings.TrimSpace(q.Get("recoveryWindowDays")); v != "" {
		windowDays, err = strconv.Atoi(v)
		if err != nil {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", "recoveryWindowDays must be a number")
			return
		}
	}
	if err := s.secretsSvc().DeleteShadowing(ctx, project, env, folder, windowDays, force); err != nil {
		if errors.Is(err, errItemNotFound) {
			writeNativeError(w, http.StatusNotFound, "not_found", "no object is shadowing that folder")
			return
		}
		writeSecretsFailure(w, http.StatusInternalServerError, "delete_failed", err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.DeleteShadowing", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"deleted": true, "forced": force})
}

// folderHasPrefix reports whether folder starts with prefix.
func folderHasPrefix(folder, prefix []string) bool {
	if len(folder) < len(prefix) {
		return false
	}
	for i := range prefix {
		if folder[i] != prefix[i] {
			return false
		}
	}
	return true
}

type nativePutSecretRequest struct {
	Project  string `json:"project"`
	Env      string `json:"env"`
	Path     string `json:"path"`
	Key      string `json:"key"`
	Value    string `json:"value"`
	KMSKeyID string `json:"kmsKeyId"`
}

// handleV1PutSecret creates or updates a single item via the secrets service.
func (s *Server) handleV1PutSecret(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativePutSecretRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	folder, err := normalizeFolder(req.Path)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	coord := itemCoord{
		Project: strings.TrimSpace(req.Project),
		Env:     strings.TrimSpace(req.Env),
		Folder:  folder,
		Key:     strings.TrimSpace(req.Key),
	}
	if err := coord.validate(); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !s.requireNoApproval(w, r, ctx, coord.Project, coord.Env, "citadel.PutItem") {
		return
	}
	created, err := s.secretsSvc().PutItem(ctx, coord, req.Value, req.KMSKeyID)
	if err != nil {
		writeSecretsFailure(w, http.StatusBadRequest, "put_failed", err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.PutItem", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"project": coord.Project, "env": coord.Env, "path": store.FolderPath(folder), "key": coord.Key, "created": created})
}

// handleV1RevealSecret returns the decrypted value of a single item (or of
// one version with versionId). Viewers may call it only where the account's
// viewersCanReveal setting allows; this also governs the console's version
// values and .env export, which are built on it.
func (s *Server) handleV1RevealSecret(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.secretsSession(w, r, "viewer")
	if !ok {
		return
	}
	q := r.URL.Query()
	coord, err := coordFromQuery(q)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !s.requireReveal(w, r, ctx, sess, "citadel.RevealItem") {
		return
	}
	resolve := strings.EqualFold(strings.TrimSpace(q.Get("resolve")), "true")
	var value store.SecretValueRecord
	if resolve {
		value, err = s.secretsSvc().RevealItemResolved(ctx, coord, q.Get("versionId"), q.Get("versionStage"))
	} else {
		value, err = s.secretsSvc().RevealItem(ctx, coord, q.Get("versionId"), q.Get("versionStage"))
	}
	if err != nil {
		writeNativeError(w, http.StatusNotFound, "not_found", "item not found")
		return
	}
	resp := map[string]any{"key": coord.Key, "versionId": value.VersionID, "resolved": resolve}
	if value.SecretString != nil {
		resp["value"] = *value.SecretString
	} else {
		resp["binaryValue"] = value.SecretBinary
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RevealItem", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, resp)
}

// handleV1DeleteSecret schedules deletion of a single item. By default it
// applies the store's recovery window so the item can be restored; pass
// force=true to set the deletion date to now, or recoveryWindowDays=N to choose
// the window. Use the restore endpoint to cancel a pending deletion.
func (s *Server) handleV1DeleteSecret(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	q := r.URL.Query()
	coord, err := coordFromQuery(q)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	force := strings.EqualFold(strings.TrimSpace(q.Get("force")), "true")
	windowDays := 0
	if v := strings.TrimSpace(q.Get("recoveryWindowDays")); v != "" {
		windowDays, err = strconv.Atoi(v)
		if err != nil {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", "recoveryWindowDays must be a number")
			return
		}
	}
	if err := s.secretsSvc().DeleteItem(ctx, coord, windowDays, force); err != nil {
		writeSecretsFailure(w, http.StatusInternalServerError, "delete_failed", err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.DeleteItem", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"deleted": true, "forced": force})
}

// coordFromQuery builds and validates an item coordinate from query params.
func coordFromQuery(q map[string][]string) (itemCoord, error) {
	get := func(k string) string {
		if v, ok := q[k]; ok && len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
		return ""
	}
	folder, err := normalizeFolder(get("path"))
	if err != nil {
		return itemCoord{}, err
	}
	coord := itemCoord{Project: get("project"), Env: get("env"), Folder: folder, Key: get("key")}
	if coord.Project == "" || coord.Env == "" || coord.Key == "" {
		return itemCoord{}, errors.New("project, env and key are required")
	}
	if err := coord.validate(); err != nil {
		return itemCoord{}, err
	}
	return coord, nil
}

// ---- P5: hierarchy structure + versions + restore --------------------------

type nativeCreateProjectRequest struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// handleV1CreateProject registers a structure-only project.
func (s *Server) handleV1CreateProject(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeCreateProjectRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.secretsSvc().CreateProject(ctx, strings.TrimSpace(req.Slug), req.Name); err != nil {
		writeSecretsFailure(w, http.StatusBadRequest, "create_failed", err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.CreateProject", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"slug": strings.TrimSpace(req.Slug), "created": true})
}

type nativeCreateEnvironmentRequest struct {
	Project string `json:"project"`
	Slug    string `json:"slug"`
	Name    string `json:"name"`
}

// handleV1CreateEnvironment registers a structure-only environment.
func (s *Server) handleV1CreateEnvironment(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeCreateEnvironmentRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.secretsSvc().CreateEnvironment(ctx, strings.TrimSpace(req.Project), strings.TrimSpace(req.Slug), req.Name); err != nil {
		writeSecretsFailure(w, http.StatusBadRequest, "create_failed", err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.CreateEnvironment", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"project": strings.TrimSpace(req.Project), "slug": strings.TrimSpace(req.Slug), "created": true})
}

type nativeCreateFolderRequest struct {
	Project string `json:"project"`
	Env     string `json:"env"`
	Path    string `json:"path"`
}

// handleV1CreateFolder registers a structure-only (possibly empty) folder.
func (s *Server) handleV1CreateFolder(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeCreateFolderRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	folder, err := normalizeFolder(req.Path)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.secretsSvc().CreateFolder(ctx, strings.TrimSpace(req.Project), strings.TrimSpace(req.Env), folder); err != nil {
		writeSecretsFailure(w, http.StatusBadRequest, "create_failed", err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.CreateFolder", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"project": strings.TrimSpace(req.Project), "env": strings.TrimSpace(req.Env), "path": store.FolderPath(folder), "created": true})
}

type nativeRenameRequest struct {
	Project string `json:"project"`
	Slug    string `json:"slug"`
	Name    string `json:"name"`
}

// handleV1RenameProject updates a project's display name.
func (s *Server) handleV1RenameProject(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeRenameRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.secretsSvc().RenameProject(ctx, strings.TrimSpace(req.Slug), req.Name); err != nil {
		writeSecretsFailure(w, http.StatusBadRequest, "rename_failed", err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RenameProject", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"slug": strings.TrimSpace(req.Slug), "renamed": true})
}

// handleV1RenameEnvironment updates an environment's display name.
func (s *Server) handleV1RenameEnvironment(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeRenameRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.secretsSvc().RenameEnvironment(ctx, strings.TrimSpace(req.Project), strings.TrimSpace(req.Slug), req.Name); err != nil {
		writeSecretsFailure(w, http.StatusBadRequest, "rename_failed", err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RenameEnvironment", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"project": strings.TrimSpace(req.Project), "slug": strings.TrimSpace(req.Slug), "renamed": true})
}

// handleV1DeleteProject removes a structure-only project (refuses if it still
// holds secrets).
func (s *Server) handleV1DeleteProject(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	slug := strings.TrimSpace(r.URL.Query().Get("project"))
	if err := s.secretsSvc().DeleteProject(ctx, slug); err != nil {
		writeSecretsFailure(w, http.StatusBadRequest, "delete_failed", err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.DeleteProject", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"slug": slug, "deleted": true})
}

// handleV1DeleteEnvironment removes a structure-only environment (refuses if it
// still holds secrets).
func (s *Server) handleV1DeleteEnvironment(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	q := r.URL.Query()
	project := strings.TrimSpace(q.Get("project"))
	slug := strings.TrimSpace(q.Get("env"))
	if err := s.secretsSvc().DeleteEnvironment(ctx, project, slug); err != nil {
		writeSecretsFailure(w, http.StatusBadRequest, "delete_failed", err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.DeleteEnvironment", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"project": project, "env": slug, "deleted": true})
}

// handleV1DeleteFolder removes a structure-only folder (refuses if it still
// holds secrets).
func (s *Server) handleV1DeleteFolder(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	q := r.URL.Query()
	project := strings.TrimSpace(q.Get("project"))
	env := strings.TrimSpace(q.Get("env"))
	folder, err := normalizeFolder(q.Get("path"))
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.secretsSvc().DeleteFolder(ctx, project, env, folder); err != nil {
		writeSecretsFailure(w, http.StatusBadRequest, "delete_failed", err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.DeleteFolder", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"project": project, "env": env, "path": store.FolderPath(folder), "deleted": true})
}

func (s *Server) handleV1ListVersions(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "viewer")
	if !ok {
		return
	}
	coord, err := coordFromQuery(r.URL.Query())
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	versions, err := s.secretsSvc().ListItemVersions(ctx, coord)
	if err != nil {
		writeNativeError(w, http.StatusNotFound, "not_found", "item not found")
		return
	}
	out := make([]map[string]any, 0, len(versions))
	for _, v := range versions {
		out = append(out, map[string]any{
			"versionId": v.VersionID,
			"stages":    v.Stages,
			"createdAt": v.CreatedAt.Format(time.RFC3339),
			"version":   v.Ordinal,
		})
		if v.CreatedBy != "" {
			out[len(out)-1]["createdBy"] = v.CreatedBy
		}
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"key": coord.Key, "versions": out})
}

// handleV1RestoreSecret cancels a pending deletion (point-in-time recovery).
func (s *Server) handleV1RestoreSecret(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	coord, err := coordFromQuery(r.URL.Query())
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !s.requireNoApproval(w, r, ctx, coord.Project, coord.Env, "citadel.RestoreItem") {
		return
	}
	if err := s.secretsSvc().RestoreItem(ctx, coord); err != nil {
		writeNativeError(w, http.StatusNotFound, "not_found", "item not found")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RestoreItem", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"restored": true})
}

// canAccessEnv is the env-scoped RBAC extension point (PLAN.md §6 P8). It is
// where per-environment grants will be consulted; today it defers to the
// caller's global role so behaviour is unchanged, while giving the rest of the
// code a single, stable hook to evolve.
func (s *Server) canAccessEnv(sess *uiSession, project, env, minRole string) bool {
	if sess == nil {
		return false
	}
	return uiRoleAtLeast(sess.Role, minRole)
}
