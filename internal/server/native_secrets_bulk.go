package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/worlddrknss/citadel/internal/store"
)

// POST /v1/secrets/bulk (editor) applies one action to several keys of a
// folder:
//
//	{action:"delete", project, env, path, keys, force?, recoveryWindowDays?}
//	{action:"restore", project, env, path, keys}                 409 approval_required in an approval env
//	{action:"copy", project, env, path, keys, targetEnv, targetPath, overwrite}
//	    copies each current value with its description, KMS key and tags;
//	    existing target keys fail unless overwrite; into an approval env one
//	    change request per key is opened instead (ids in changeRequests);
//	    audit citadel.BulkCopy
//	{action:"move", project, env, path, keys, targetPath}
//	    renames within the environment, keeping history, tags and policy;
//	    409 approval_required in an approval env; audit citadel.BulkMove
//
// -> 200 {applied, failed[], changeRequests?[]}

const maxBulkKeys = 500

type nativeBulkRequest struct {
	Project            string   `json:"project"`
	Env                string   `json:"env"`
	Path               string   `json:"path"`
	Keys               []string `json:"keys"`
	Action             string   `json:"action"`
	Force              bool     `json:"force"`
	RecoveryWindowDays int      `json:"recoveryWindowDays"`
	TargetEnv          string   `json:"targetEnv"`
	TargetPath         string   `json:"targetPath"`
	Overwrite          bool     `json:"overwrite"`
}

func (s *Server) handleV1BulkSecrets(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeBulkRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "request body must be a JSON object")
		return
	}
	if len(req.Keys) > maxBulkKeys {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "at most 500 keys per request")
		return
	}
	req.Project, req.Env = strings.TrimSpace(req.Project), strings.TrimSpace(req.Env)
	if err := validateSegment("project", req.Project); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := validateSegment("env", req.Env); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	switch action := strings.ToLower(strings.TrimSpace(req.Action)); action {
	case "delete", "restore":
		s.bulkDeleteRestore(w, r, ctx, req, action)
	case "copy":
		s.bulkCopy(w, r, ctx, sess, req)
	case "move":
		s.bulkMove(w, r, ctx, req)
	default:
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "action must be delete, restore, copy or move")
	}
}

func (s *Server) bulkDeleteRestore(w http.ResponseWriter, r *http.Request, ctx context.Context, req nativeBulkRequest, action string) {
	if action == "restore" && !s.requireNoApproval(w, r, ctx, req.Project, req.Env, "citadel.Bulk:restore") {
		return
	}
	svc := s.secretsSvc()
	applied, failed := 0, make([]string, 0)
	for _, key := range req.Keys {
		coord, err := coordFromParts(req.Project, req.Env, req.Path, key)
		if err != nil {
			failed = append(failed, strings.TrimSpace(key))
			continue
		}
		if action == "delete" {
			err = svc.DeleteItem(ctx, coord, req.RecoveryWindowDays, req.Force)
		} else {
			err = svc.RestoreItem(ctx, coord)
		}
		if err != nil {
			failed = append(failed, coord.Key)
			continue
		}
		applied++
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.Bulk:" + action, Result: bulkResult(applied, failed), AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"applied": applied, "failed": failed})
}

func bulkResult(applied int, failed []string) string {
	if len(failed) > 0 && applied == 0 {
		return "error"
	}
	return "ok"
}

func (s *Server) bulkCopy(w http.ResponseWriter, r *http.Request, ctx context.Context, sess *uiSession, req nativeBulkRequest) {
	targetEnv := strings.TrimSpace(req.TargetEnv)
	if err := validateSegment("targetEnv", targetEnv); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	srcFolder, err := normalizeFolder(req.Path)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	dstFolder, err := normalizeFolder(req.TargetPath)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if targetEnv == req.Env && store.FolderPath(srcFolder) == store.FolderPath(dstFolder) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "the target is the same folder as the source")
		return
	}
	_, needsApproval, err := s.approvalPolicyFor(ctx, req.Project, targetEnv)
	if err != nil {
		log.Printf("bulk copy: approval policy: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not check approval policy")
		return
	}
	svc := s.secretsSvc()
	applied, failed, crs := 0, make([]string, 0), make([]string, 0)
	for _, raw := range req.Keys {
		key := strings.TrimSpace(raw)
		src := itemCoord{Project: req.Project, Env: req.Env, Folder: srcFolder, Key: key}
		dst := itemCoord{Project: req.Project, Env: targetEnv, Folder: dstFolder, Key: key}
		if src.validate() != nil {
			failed = append(failed, key)
			continue
		}
		meta, err := s.store.DescribeSecret(ctx, src.backingName())
		if err != nil || meta.DeletedDate != nil {
			failed = append(failed, key)
			continue
		}
		value, err := svc.RevealItem(ctx, src, "", "")
		if err != nil {
			failed = append(failed, key)
			continue
		}
		existing, existsErr := s.store.DescribeSecret(ctx, dst.backingName())
		exists := existsErr == nil
		if exists && !req.Overwrite {
			failed = append(failed, key)
			continue
		}
		if needsApproval {
			if value.SecretString == nil {
				failed = append(failed, key) // change requests carry text values only
				continue
			}
			cr, err := s.newChangeRequest(ctx, sess, dst, *value.SecretString, meta.KMSKeyID, "Copy "+key+" from "+req.Env, "")
			if err != nil {
				log.Printf("bulk copy: change request: %v", err)
				failed = append(failed, key)
				continue
			}
			crs = append(crs, cr.ID)
			continue
		}
		if err := s.copySecretValue(ctx, meta, value, dst, exists && existing.DeletedDate == nil, exists); err != nil {
			log.Printf("bulk copy %s: %v", key, err)
			failed = append(failed, key)
			continue
		}
		applied++
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.BulkCopy", Result: bulkResult(applied+len(crs), failed), AuditOrigin: s.auditOrigin(r)})
	resp := map[string]any{"applied": applied, "failed": failed}
	if len(crs) > 0 {
		resp["changeRequests"] = crs
	}
	writeNativeJSON(w, http.StatusOK, resp)
}

// copySecretValue writes value (with the source's description, KMS key and
// tags) to dst, creating it or adding a version to it.
func (s *Server) copySecretValue(ctx context.Context, src store.SecretMetadataRecord, value store.SecretValueRecord, dst itemCoord, live, exists bool) error {
	name := dst.backingName()
	if exists && !live {
		return errors.New("target is scheduled for deletion")
	}
	str := ""
	if value.SecretString != nil {
		str = *value.SecretString
	}
	if exists {
		if _, err := s.store.PutSecretValue(ctx, store.PutSecretValueRequest{SecretID: name, SecretString: str, SecretBinary: value.SecretBinary}); err != nil {
			return err
		}
	} else if _, _, err := s.store.CreateSecret(ctx, store.CreateSecretRequest{Name: name, Description: src.Description, KMSKeyID: src.KMSKeyID, SecretString: str, SecretBinary: value.SecretBinary}); err != nil {
		return err
	}
	if len(src.Tags) > 0 {
		return s.store.TagSecret(ctx, name, src.Tags)
	}
	return nil
}

func (s *Server) bulkMove(w http.ResponseWriter, r *http.Request, ctx context.Context, req nativeBulkRequest) {
	srcFolder, err := normalizeFolder(req.Path)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	dstFolder, err := normalizeFolder(req.TargetPath)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if store.FolderPath(srcFolder) == store.FolderPath(dstFolder) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "the target is the same folder as the source")
		return
	}
	if !s.requireNoApproval(w, r, ctx, req.Project, req.Env, "citadel.BulkMove") {
		return
	}
	applied, failed := 0, make([]string, 0)
	for _, raw := range req.Keys {
		key := strings.TrimSpace(raw)
		src := itemCoord{Project: req.Project, Env: req.Env, Folder: srcFolder, Key: key}
		dst := itemCoord{Project: req.Project, Env: req.Env, Folder: dstFolder, Key: key}
		if src.validate() != nil {
			failed = append(failed, key)
			continue
		}
		if _, err := s.store.RenameSecret(ctx, src.backingName(), dst.backingName()); err != nil {
			failed = append(failed, key)
			continue
		}
		applied++
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.BulkMove", Result: bulkResult(applied, failed), AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"applied": applied, "failed": failed})
}
