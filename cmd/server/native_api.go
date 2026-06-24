package main

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

// nativeSession resolves the caller's UI session for the native API. Unlike
// requireUISession (which redirects browsers to the login page), it returns a
// JSON 401 so the SPA can react programmatically. It also returns a context
// scoped to the session's account so the underlying store applies per-account
// isolation via the existing accountFilter plumbing.
func (s *server) nativeSession(w http.ResponseWriter, r *http.Request, minRole string) (*uiSession, context.Context, bool) {
	runtime := s.uiRuntime()
	// Bearer token auth (machine identities) takes precedence over cookies so
	// native SDKs and CI can talk to /v1 without a browser session.
	if sess, ctx, ok, handled := s.nativeTokenSession(w, r, minRole); handled {
		return sess, ctx, ok
	}
	if !runtime.enabled {
		sess := &uiSession{Username: "local", Role: "admin", DisplayName: "Local Admin"}
		return sess, r.Context(), true
	}
	cookie, err := r.Cookie(adminSessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		writeNativeError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return nil, nil, false
	}
	runtime.mu.Lock()
	session, ok := runtime.sessions[cookie.Value]
	now := time.Now().UTC()
	if ok && sessionExpired(session, now, runtime.idleTTL, runtime.absoluteTTL) {
		delete(runtime.sessions, cookie.Value)
		ok = false
	}
	if ok {
		session.LastSeenAt = now
		runtime.sessions[cookie.Value] = session
	}
	runtime.mu.Unlock()
	if !ok {
		writeNativeError(w, http.StatusUnauthorized, "unauthorized", "session expired")
		return nil, nil, false
	}
	if !uiRoleAtLeast(session.Role, minRole) {
		writeNativeError(w, http.StatusForbidden, "forbidden", "insufficient role")
		return nil, nil, false
	}
	// Scope the request context to the session's current account so the store's
	// accountFilter/accountForContext helpers isolate reads and stamp writes.
	ctx := withCallerAccount(r.Context(), strings.TrimSpace(session.AccountID))
	return &session, ctx, true
}

// nativeTokenSession authenticates a machine identity from an Authorization:
// Bearer "<accessKeyId>:<secret>" header. It returns handled=false when no
// bearer token is present (so the caller falls back to cookie auth). When a
// token is present it is fully resolved here: ok reports success, and the
// request context is scoped to the token's account for per-tenant isolation.
func (s *server) nativeTokenSession(w http.ResponseWriter, r *http.Request, minRole string) (sess *uiSession, ctx context.Context, ok bool, handled bool) {
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
	_, accountID, storedSecret, status, err := s.store.GetAccessKeyByID(r.Context(), keyID)
	if err != nil || strings.ToLower(status) != "active" {
		writeNativeError(w, http.StatusUnauthorized, "unauthorized", "invalid or inactive token")
		return nil, nil, false, true
	}
	if subtle.ConstantTimeCompare([]byte(secret), []byte(storedSecret)) != 1 {
		writeNativeError(w, http.StatusUnauthorized, "unauthorized", "invalid or inactive token")
		return nil, nil, false, true
	}
	// Machine identities act as account-scoped administrators for the native
	// API; the role gate below still applies for completeness.
	const tokenRole = "admin"
	if !uiRoleAtLeast(tokenRole, minRole) {
		writeNativeError(w, http.StatusForbidden, "forbidden", "insufficient role")
		return nil, nil, false, true
	}
	_ = s.store.TouchAccessKeyLastUsed(r.Context(), keyID)
	sess = &uiSession{Username: keyID, Role: tokenRole, AccountID: accountID, DisplayName: "Machine Identity"}
	ctx = withCallerAccount(r.Context(), strings.TrimSpace(accountID))
	return sess, ctx, true, true
}

// verifyNativeOIDC is the native OIDC identity extension point (PLAN.md §6 P9).
// When a future deployment configures an OIDC issuer/audience, this is where a
// JWT bearer would be validated and mapped to an account-scoped session. It is
// currently a no-op scaffold that reports ok=false so callers fall through to
// the existing access-key and cookie auth paths, leaving behaviour unchanged.
func (s *server) verifyNativeOIDC(r *http.Request, token string) (*uiSession, context.Context, bool) {
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

// folderPath renders folder segments back into a canonical "/a/b" string. Root
// is rendered as "/".
func folderPath(segs []string) string {
	if len(segs) == 0 {
		return "/"
	}
	return "/" + strings.Join(segs, "/")
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
}

type nativeItem struct {
	Project      string `json:"project"`
	Env          string `json:"env"`
	Path         string `json:"path"`
	Key          string `json:"key"`
	ARN          string `json:"arn"`
	UpdatedAt    string `json:"updatedAt"`
	DeletionDate string `json:"deletionDate,omitempty"`
}

// ---- handlers --------------------------------------------------------------

func (s *server) handleV1Me(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	writeNativeJSON(w, http.StatusOK, nativeMeResponse{
		Username:    sess.Username,
		DisplayName: sess.DisplayName,
		Role:        sess.Role,
		AccountID:   sess.AccountID,
		Accounts:    sess.Accounts,
	})
}

// handleV1Projects returns the distinct projects (and their environments)
// visible to the caller's account, via the shared secrets service.
func (s *server) handleV1Projects(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	projects, err := s.secretsSvc().ListProjects(ctx)
	if err != nil {
		writeNativeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	out := make([]nativeProject, 0, len(projects))
	for _, p := range projects {
		out = append(out, nativeProject{Slug: p.Slug, Environments: p.Environments})
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"projects": out})
}

// handleV1ListSecrets lists the items at a given project/env/folder. Values are
// never included; callers must use the reveal endpoint for a single item.
func (s *server) handleV1ListSecrets(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
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
	folders, found, err := s.secretsSvc().ListFolder(ctx, project, env, wantFolder)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	items := make([]nativeItem, 0, len(found))
	for _, it := range found {
		ni := nativeItem{
			Project:   it.Project,
			Env:       it.Env,
			Path:      it.Path,
			Key:       it.Key,
			ARN:       it.ARN,
			UpdatedAt: it.UpdatedAt.Format(time.RFC3339),
		}
		if it.DeletionDate != nil {
			ni.DeletionDate = it.DeletionDate.Format(time.RFC3339)
		}
		items = append(items, ni)
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{
		"project": project,
		"env":     env,
		"path":    folderPath(wantFolder),
		"folders": folders,
		"items":   items,
	})
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
func (s *server) handleV1PutSecret(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
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
	created, err := s.secretsSvc().PutItem(ctx, coord, req.Value, req.KMSKeyID)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "put_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.PutItem", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"project": coord.Project, "env": coord.Env, "path": folderPath(folder), "key": coord.Key, "created": created})
}

// handleV1RevealSecret returns the decrypted value of a single item.
func (s *server) handleV1RevealSecret(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	q := r.URL.Query()
	coord, err := coordFromQuery(q)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	resolve := strings.EqualFold(strings.TrimSpace(q.Get("resolve")), "true")
	var value secretValueRecord
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
	s.recordAudit(ctx, auditEvent{Action: "citadel.RevealItem", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, resp)
}

// handleV1DeleteSecret schedules deletion of a single item. By default it
// applies the store's recovery window so the item can be restored; pass
// force=true to set the deletion date to now, or recoveryWindowDays=N to choose
// the window. Use the restore endpoint to cancel a pending deletion.
func (s *server) handleV1DeleteSecret(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
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
		writeNativeError(w, http.StatusInternalServerError, "delete_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.DeleteItem", Result: "ok", Actor: r.RemoteAddr})
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
func (s *server) handleV1CreateProject(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeCreateProjectRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.secretsSvc().CreateProject(ctx, strings.TrimSpace(req.Slug), req.Name); err != nil {
		writeNativeError(w, http.StatusBadRequest, "create_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.CreateProject", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"slug": strings.TrimSpace(req.Slug), "created": true})
}

type nativeCreateEnvironmentRequest struct {
	Project string `json:"project"`
	Slug    string `json:"slug"`
	Name    string `json:"name"`
}

// handleV1CreateEnvironment registers a structure-only environment.
func (s *server) handleV1CreateEnvironment(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeCreateEnvironmentRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.secretsSvc().CreateEnvironment(ctx, strings.TrimSpace(req.Project), strings.TrimSpace(req.Slug), req.Name); err != nil {
		writeNativeError(w, http.StatusBadRequest, "create_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.CreateEnvironment", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"project": strings.TrimSpace(req.Project), "slug": strings.TrimSpace(req.Slug), "created": true})
}

type nativeCreateFolderRequest struct {
	Project string `json:"project"`
	Env     string `json:"env"`
	Path    string `json:"path"`
}

// handleV1CreateFolder registers a structure-only (possibly empty) folder.
func (s *server) handleV1CreateFolder(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
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
		writeNativeError(w, http.StatusBadRequest, "create_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.CreateFolder", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"project": strings.TrimSpace(req.Project), "env": strings.TrimSpace(req.Env), "path": folderPath(folder), "created": true})
}

// handleV1ListVersions returns the version history of a single item.
func (s *server) handleV1ListVersions(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
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
		})
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"key": coord.Key, "versions": out})
}

// handleV1RestoreSecret cancels a pending deletion (point-in-time recovery).
func (s *server) handleV1RestoreSecret(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	coord, err := coordFromQuery(r.URL.Query())
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.secretsSvc().RestoreItem(ctx, coord); err != nil {
		writeNativeError(w, http.StatusNotFound, "not_found", "item not found")
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.RestoreItem", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"restored": true})
}

// canAccessEnv is the env-scoped RBAC extension point (PLAN.md §6 P8). It is
// where per-environment grants will be consulted; today it defers to the
// caller's global role so behaviour is unchanged, while giving the rest of the
// code a single, stable hook to evolve.
func (s *server) canAccessEnv(sess *uiSession, project, env, minRole string) bool {
	if sess == nil {
		return false
	}
	return uiRoleAtLeast(sess.Role, minRole)
}

func changeRequestJSON(cr changeRequest) map[string]any {
	out := map[string]any{
		"id":        cr.ID,
		"project":   cr.Coord.Project,
		"env":       cr.Coord.Env,
		"path":      folderPath(cr.Coord.Folder),
		"key":       cr.Coord.Key,
		"requester": cr.Requester,
		"status":    string(cr.Status),
		"createdAt": cr.CreatedAt.Format(time.RFC3339),
	}
	if cr.DecidedBy != "" {
		out["decidedBy"] = cr.DecidedBy
		out["decidedAt"] = cr.DecidedAt.Format(time.RFC3339)
	}
	return out
}

type nativeChangeRequestBody struct {
	Project string `json:"project"`
	Env     string `json:"env"`
	Path    string `json:"path"`
	Key     string `json:"key"`
	Value   string `json:"value"`
	ID      string `json:"id"`
}

// handleV1CreateChangeRequest records a proposed write awaiting approval.
func (s *server) handleV1CreateChangeRequest(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeChangeRequestBody
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	folder, err := normalizeFolder(req.Path)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	coord := itemCoord{Project: strings.TrimSpace(req.Project), Env: strings.TrimSpace(req.Env), Folder: folder, Key: strings.TrimSpace(req.Key)}
	if !s.canAccessEnv(sess, coord.Project, coord.Env, "editor") {
		writeNativeError(w, http.StatusForbidden, "forbidden", "insufficient environment access")
		return
	}
	cr, err := s.secretsSvc().CreateChangeRequest(ctx, coord, req.Value, "", sess.Username)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "create_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.CreateChangeRequest", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, changeRequestJSON(*cr))
}

// handleV1ListChangeRequests lists the caller account's change requests.
func (s *server) handleV1ListChangeRequests(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	requests := s.secretsSvc().ListChangeRequests(ctx)
	out := make([]map[string]any, 0, len(requests))
	for _, cr := range requests {
		out = append(out, changeRequestJSON(cr))
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"changeRequests": out})
}

// handleV1ApproveChangeRequest approves and applies a pending change request.
func (s *server) handleV1ApproveChangeRequest(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req nativeChangeRequestBody
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.secretsSvc().ApproveChangeRequest(ctx, strings.TrimSpace(req.ID), sess.Username); err != nil {
		writeNativeError(w, http.StatusBadRequest, "approve_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.ApproveChangeRequest", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"approved": true, "id": strings.TrimSpace(req.ID)})
}

// handleV1RejectChangeRequest rejects a pending change request.
func (s *server) handleV1RejectChangeRequest(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req nativeChangeRequestBody
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.secretsSvc().RejectChangeRequest(ctx, strings.TrimSpace(req.ID), sess.Username); err != nil {
		writeNativeError(w, http.StatusBadRequest, "reject_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.RejectChangeRequest", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"rejected": true, "id": strings.TrimSpace(req.ID)})
}
