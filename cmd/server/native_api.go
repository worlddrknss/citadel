package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"
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
	Project   string `json:"project"`
	Env       string `json:"env"`
	Path      string `json:"path"`
	Key       string `json:"key"`
	ARN       string `json:"arn"`
	UpdatedAt string `json:"updatedAt"`
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
// derived from the names of the secrets visible to the caller's account.
func (s *server) handleV1Projects(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	secrets, err := s.store.ListSecrets(ctx)
	if err != nil {
		writeNativeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	envsByProject := map[string]map[string]struct{}{}
	for _, sec := range secrets {
		pi, ok := parseSecretName(sec.Name)
		if !ok {
			continue
		}
		if _, exists := envsByProject[pi.Project]; !exists {
			envsByProject[pi.Project] = map[string]struct{}{}
		}
		envsByProject[pi.Project][pi.Env] = struct{}{}
	}
	projects := make([]nativeProject, 0, len(envsByProject))
	for project, envSet := range envsByProject {
		envs := make([]string, 0, len(envSet))
		for e := range envSet {
			envs = append(envs, e)
		}
		sort.Strings(envs)
		projects = append(projects, nativeProject{Slug: project, Environments: envs})
	}
	sort.Slice(projects, func(i, j int) bool { return projects[i].Slug < projects[j].Slug })
	writeNativeJSON(w, http.StatusOK, map[string]any{"projects": projects})
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
	if err := validateSegment("project", project); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := validateSegment("env", env); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	wantFolder, err := normalizeFolder(q.Get("path"))
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	secrets, err := s.store.ListSecrets(ctx)
	if err != nil {
		writeNativeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	items := make([]nativeItem, 0)
	subfolders := map[string]struct{}{}
	for _, sec := range secrets {
		pi, ok := parseSecretName(sec.Name)
		if !ok || pi.Project != project || pi.Env != env {
			continue
		}
		if !folderHasPrefix(pi.Folder, wantFolder) {
			continue
		}
		if len(pi.Folder) == len(wantFolder) {
			items = append(items, nativeItem{
				Project:   pi.Project,
				Env:       pi.Env,
				Path:      folderPath(pi.Folder),
				Key:       pi.Key,
				ARN:       sec.ARN,
				UpdatedAt: sec.LastChangedDate.UTC().Format(time.RFC3339),
			})
		} else {
			// Immediate subfolder of the requested path.
			subfolders[pi.Folder[len(wantFolder)]] = struct{}{}
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Key < items[j].Key })
	folders := make([]string, 0, len(subfolders))
	for f := range subfolders {
		folders = append(folders, f)
	}
	sort.Strings(folders)
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

// handleV1PutSecret creates or updates a single item. It maps to CreateSecret on
// first write and PutSecretValue on subsequent writes, so versioning is handled
// by the existing store.
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
	req.Project = strings.TrimSpace(req.Project)
	req.Env = strings.TrimSpace(req.Env)
	req.Key = strings.TrimSpace(req.Key)
	for field, val := range map[string]string{"project": req.Project, "env": req.Env, "key": req.Key} {
		if val == "" {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", field+" is required")
			return
		}
		if err := validateSegment(field, val); err != nil {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
	}
	folder, err := normalizeFolder(req.Path)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	name := flatSecretName(req.Project, req.Env, folder, req.Key)

	if _, err := s.store.DescribeSecret(ctx, name); err != nil {
		// Treat any lookup miss as "create".
		_, _, createErr := s.store.CreateSecret(ctx, createSecretRequest{
			Name:         name,
			Description:  "citadel:" + req.Project + "/" + req.Env,
			KMSKeyID:     strings.TrimSpace(req.KMSKeyID),
			SecretString: req.Value,
		})
		if createErr != nil {
			writeNativeError(w, http.StatusInternalServerError, "create_failed", createErr.Error())
			return
		}
		s.recordAudit(ctx, auditEvent{Action: "citadel.PutItem", Result: "ok", Actor: r.RemoteAddr})
		writeNativeJSON(w, http.StatusOK, map[string]any{"project": req.Project, "env": req.Env, "path": folderPath(folder), "key": req.Key, "created": true})
		return
	}
	if _, err := s.store.PutSecretValue(ctx, putSecretValueRequest{SecretID: name, SecretString: req.Value}); err != nil {
		writeNativeError(w, http.StatusInternalServerError, "update_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.PutItem", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"project": req.Project, "env": req.Env, "path": folderPath(folder), "key": req.Key, "created": false})
}

// handleV1RevealSecret returns the decrypted value of a single item.
func (s *server) handleV1RevealSecret(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	q := r.URL.Query()
	name, err := nameFromQuery(q)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	value, err := s.store.GetSecretValue(ctx, name, "", "")
	if err != nil {
		writeNativeError(w, http.StatusNotFound, "not_found", "item not found")
		return
	}
	resp := map[string]any{"key": q.Get("key"), "versionId": value.VersionID}
	if value.SecretString != nil {
		resp["value"] = *value.SecretString
	} else {
		resp["binaryValue"] = value.SecretBinary
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.RevealItem", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, resp)
}

// handleV1DeleteSecret schedules deletion of a single item.
func (s *server) handleV1DeleteSecret(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	name, err := nameFromQuery(r.URL.Query())
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if _, err := s.store.DeleteSecret(ctx, name, 0, true); err != nil {
		writeNativeError(w, http.StatusInternalServerError, "delete_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.DeleteItem", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// nameFromQuery builds and validates a backing secret name from query params.
func nameFromQuery(q map[string][]string) (string, error) {
	get := func(k string) string {
		if v, ok := q[k]; ok && len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
		return ""
	}
	project, env, key := get("project"), get("env"), get("key")
	if project == "" || env == "" || key == "" {
		return "", errors.New("project, env and key are required")
	}
	for field, val := range map[string]string{"project": project, "env": env, "key": key} {
		if err := validateSegment(field, val); err != nil {
			return "", err
		}
	}
	folder, err := normalizeFolder(get("path"))
	if err != nil {
		return "", err
	}
	return flatSecretName(project, env, folder, key), nil
}
