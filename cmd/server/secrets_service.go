package main

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"time"
)

// secretsService is the protocol-free business layer for the Infisical-style
// secrets model. It contains no net/http and no AWS X-Amz types in its
// signatures, so every front door — the native /v1 API, the AWS-compatibility
// facade, and the Svelte UI — can share exactly the same logic (PLAN.md §3
// "one shared service layer").
//
// Item VALUES are persisted through the existing AWS-compatible secrets store
// (keyStore) so External Secrets Operator and the AWS SDK keep reading them
// unchanged. Optional hierarchy STRUCTURE (projects / environments / empty
// folders) is persisted through hierarchyStore when available, which lets the
// UI model folders that do not yet contain any items.
type secretsService struct {
	store     keyStore
	hierarchy hierarchyStore
	approvals *approvalRegistry
}

func newSecretsService(store keyStore) *secretsService {
	svc := &secretsService{store: store, approvals: newApprovalRegistry()}
	if hs, ok := store.(hierarchyStore); ok {
		svc.hierarchy = hs
	}
	return svc
}

// itemCoord identifies a single secret item within the native hierarchy.
type itemCoord struct {
	Project string
	Env     string
	Folder  []string // folder segments, empty == root
	Key     string
}

func (c itemCoord) backingName() string {
	return flatSecretName(c.Project, c.Env, c.Folder, c.Key)
}

func (c itemCoord) validate() error {
	if err := validateSegment("project", c.Project); err != nil {
		return err
	}
	if err := validateSegment("env", c.Env); err != nil {
		return err
	}
	for _, seg := range c.Folder {
		if err := validateSegment("folder", seg); err != nil {
			return err
		}
	}
	return validateSegment("key", c.Key)
}

// projectSummary is a project plus the environments observed within it.
type projectSummary struct {
	Slug         string
	Environments []string
}

// itemSummary is an item without its (secret) value.
type itemSummary struct {
	Project      string
	Env          string
	Path         string
	Key          string
	ARN          string
	UpdatedAt    time.Time
	DeletionDate *time.Time
}

// itemDetail is the full metadata projection for a single item, backing the
// SPA detail drawer (overview / versions / tags / policy / rotation).
type itemDetail struct {
	Project           string
	Env               string
	Path              string
	Key               string
	ARN               string
	Description       string
	KMSKeyID          string
	CurrentVersionID  string
	PreviousVersionID string
	CreatedAt         time.Time
	UpdatedAt         time.Time
	DeletionDate      *time.Time
	Tags              []secretTag
	PolicyDocument    string
	RotationEnabled   bool
	RotationLambdaARN string
	RotationDays      int
	NextRotationDate  *time.Time
}

// itemVersion is one historical version of an item, newest first when sorted.
type itemVersion struct {
	VersionID string
	Stages    []string
	CreatedAt time.Time
}

var errItemNotFound = errors.New("item not found")

// ListProjects derives the visible projects and their environments from the
// names of the caller's secrets, then merges in any structure-only projects and
// environments registered via the hierarchy store.
func (svc *secretsService) ListProjects(ctx context.Context) ([]projectSummary, error) {
	secrets, err := svc.store.ListSecrets(ctx)
	if err != nil {
		return nil, err
	}
	envsByProject := map[string]map[string]struct{}{}
	addEnv := func(project, env string) {
		if _, ok := envsByProject[project]; !ok {
			envsByProject[project] = map[string]struct{}{}
		}
		if env != "" {
			envsByProject[project][env] = struct{}{}
		}
	}
	for _, sec := range secrets {
		if pi, ok := parseSecretName(sec.Name); ok {
			addEnv(pi.Project, pi.Env)
		}
	}
	if svc.hierarchy != nil {
		structure, err := svc.hierarchy.ListHierarchy(ctx)
		if err == nil {
			for _, p := range structure {
				addEnv(p.Project, "")
				for _, e := range p.Environments {
					addEnv(p.Project, e)
				}
			}
		}
	}
	out := make([]projectSummary, 0, len(envsByProject))
	for project, envSet := range envsByProject {
		envs := make([]string, 0, len(envSet))
		for e := range envSet {
			envs = append(envs, e)
		}
		sort.Strings(envs)
		out = append(out, projectSummary{Slug: project, Environments: envs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, nil
}

// ListFolder returns the immediate subfolders and the items located directly at
// the requested project/env/folder path.
func (svc *secretsService) ListFolder(ctx context.Context, project, env string, folder []string) (folders []string, items []itemSummary, err error) {
	if err = validateSegment("project", project); err != nil {
		return nil, nil, err
	}
	if err = validateSegment("env", env); err != nil {
		return nil, nil, err
	}
	secrets, err := svc.store.ListSecrets(ctx)
	if err != nil {
		return nil, nil, err
	}
	items = make([]itemSummary, 0)
	subfolders := map[string]struct{}{}
	for _, sec := range secrets {
		pi, ok := parseSecretName(sec.Name)
		if !ok || pi.Project != project || pi.Env != env {
			continue
		}
		if !folderHasPrefix(pi.Folder, folder) {
			continue
		}
		if len(pi.Folder) == len(folder) {
			items = append(items, itemSummary{
				Project:      pi.Project,
				Env:          pi.Env,
				Path:         folderPath(pi.Folder),
				Key:          pi.Key,
				ARN:          sec.ARN,
				UpdatedAt:    sec.LastChangedDate.UTC(),
				DeletionDate: sec.DeletedDate,
			})
		} else {
			subfolders[pi.Folder[len(folder)]] = struct{}{}
		}
	}
	if svc.hierarchy != nil {
		extra, herr := svc.hierarchy.ListFolders(ctx, project, env, folder)
		if herr == nil {
			for _, f := range extra {
				subfolders[f] = struct{}{}
			}
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Key < items[j].Key })
	folders = make([]string, 0, len(subfolders))
	for f := range subfolders {
		folders = append(folders, f)
	}
	sort.Strings(folders)
	return folders, items, nil
}

// PutItem creates or updates a single item, returning created=true on first
// write. Versioning is delegated to the underlying store.
func (svc *secretsService) PutItem(ctx context.Context, coord itemCoord, value, kmsKeyID string) (created bool, err error) {
	if err = coord.validate(); err != nil {
		return false, err
	}
	name := coord.backingName()
	if _, derr := svc.store.DescribeSecret(ctx, name); derr != nil {
		if _, _, cerr := svc.store.CreateSecret(ctx, createSecretRequest{
			Name:         name,
			Description:  "citadel:" + coord.Project + "/" + coord.Env,
			KMSKeyID:     strings.TrimSpace(kmsKeyID),
			SecretString: value,
		}); cerr != nil {
			return false, cerr
		}
		return true, nil
	}
	if _, perr := svc.store.PutSecretValue(ctx, putSecretValueRequest{SecretID: name, SecretString: value}); perr != nil {
		return false, perr
	}
	return false, nil
}

// RevealItem returns the decrypted value (and version) of a single item.
func (svc *secretsService) RevealItem(ctx context.Context, coord itemCoord, versionID, versionStage string) (secretValueRecord, error) {
	if err := coord.validate(); err != nil {
		return secretValueRecord{}, err
	}
	val, err := svc.store.GetSecretValue(ctx, coord.backingName(), versionID, versionStage)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return secretValueRecord{}, errItemNotFound
		}
		return secretValueRecord{}, err
	}
	return val, nil
}

// referenceDepthLimit bounds how many nested ${...} references are expanded,
// preventing reference cycles from looping forever (PLAN.md §6 P8).
const referenceDepthLimit = 8

// RevealItemResolved is like RevealItem but expands any ${KEY} /
// ${/abs/path/KEY} references contained in the value against the same
// environment before returning it (PLAN.md §6 P8 "secret references").
func (svc *secretsService) RevealItemResolved(ctx context.Context, coord itemCoord, versionID, versionStage string) (secretValueRecord, error) {
	val, err := svc.RevealItem(ctx, coord, versionID, versionStage)
	if err != nil {
		return val, err
	}
	if val.SecretString != nil {
		resolved := svc.resolveReferences(ctx, coord, *val.SecretString, referenceDepthLimit)
		val.SecretString = &resolved
	}
	return val, nil
}

// DeleteItem schedules deletion of a single item. forceDelete removes it
// immediately; otherwise the store's recovery window applies (PITR support).
func (svc *secretsService) DeleteItem(ctx context.Context, coord itemCoord, recoveryWindowDays int, forceDelete bool) error {
	if err := coord.validate(); err != nil {
		return err
	}
	if _, err := svc.store.DeleteSecret(ctx, coord.backingName(), recoveryWindowDays, forceDelete); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errItemNotFound
		}
		return err
	}
	return nil
}

// RestoreItem cancels a pending deletion (point-in-time recovery).
func (svc *secretsService) RestoreItem(ctx context.Context, coord itemCoord) error {
	if err := coord.validate(); err != nil {
		return err
	}
	if _, err := svc.store.RestoreSecret(ctx, coord.backingName()); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errItemNotFound
		}
		return err
	}
	return nil
}

// ListItemVersions returns the version history of a single item, newest first.
func (svc *secretsService) ListItemVersions(ctx context.Context, coord itemCoord) ([]itemVersion, error) {
	if err := coord.validate(); err != nil {
		return nil, err
	}
	entries, err := svc.store.ListSecretVersionIDs(ctx, coord.backingName())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errItemNotFound
		}
		return nil, err
	}
	out := make([]itemVersion, 0, len(entries))
	for _, e := range entries {
		out = append(out, itemVersion{
			VersionID: e.VersionID,
			Stages:    e.VersionStages,
			CreatedAt: time.Time(e.CreatedDate).UTC(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// FolderJSON returns a map of KEY->value for every item located directly in the
// given project/env/folder. This backs the "folder = one AWS secret (JSON of
// all keys)" projection shape (PLAN.md §5).
func (svc *secretsService) FolderJSON(ctx context.Context, project, env string, folder []string) (map[string]string, error) {
	_, items, err := svc.ListFolder(ctx, project, env, folder)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(items))
	for _, it := range items {
		val, verr := svc.store.GetSecretValue(ctx, flatSecretName(project, env, folder, it.Key), "", "")
		if verr != nil {
			continue
		}
		if val.SecretString != nil {
			out[it.Key] = *val.SecretString
		}
	}
	return out, nil
}

// FolderJSONByName interprets name as a folder coordinate (project/env/folder)
// and returns the JSON-of-all-keys projection for it. ok is false when name
// cannot be a folder or no items exist directly within it. This lets the AWS
// GetSecretValue facade serve BOTH the per-key shape and the per-folder shape
// from the same backing items (PLAN.md §5 P4), keeping ESO compatibility.
func (svc *secretsService) FolderJSONByName(ctx context.Context, name string) (map[string]string, bool, error) {
	parts := strings.Split(strings.Trim(name, "/"), "/")
	if len(parts) < 2 {
		return nil, false, nil
	}
	project, env := parts[0], parts[1]
	folder := parts[2:]
	if err := validateSegment("project", project); err != nil {
		return nil, false, nil
	}
	if err := validateSegment("env", env); err != nil {
		return nil, false, nil
	}
	for _, seg := range folder {
		if validateSegment("folder", seg) != nil {
			return nil, false, nil
		}
	}
	values, err := svc.FolderJSON(ctx, project, env, folder)
	if err != nil {
		return nil, false, err
	}
	if len(values) == 0 {
		return nil, false, nil
	}
	return values, true, nil
}

// resolveReferences expands ${KEY} and ${/abs/path/KEY} references within a
// value against the same project/env. References that cannot be resolved are
// left intact. A depth limit prevents reference cycles (PLAN.md §6 P8).
func (svc *secretsService) resolveReferences(ctx context.Context, coord itemCoord, value string, depth int) string {
	if depth <= 0 || !strings.Contains(value, "${") {
		return value
	}
	var b strings.Builder
	for {
		start := strings.Index(value, "${")
		if start < 0 {
			b.WriteString(value)
			break
		}
		end := strings.Index(value[start:], "}")
		if end < 0 {
			b.WriteString(value)
			break
		}
		end += start
		b.WriteString(value[:start])
		ref := strings.TrimSpace(value[start+2 : end])
		b.WriteString(svc.resolveOneReference(ctx, coord, ref, depth))
		value = value[end+1:]
	}
	return b.String()
}

func (svc *secretsService) resolveOneReference(ctx context.Context, coord itemCoord, ref string, depth int) string {
	target := itemCoord{Project: coord.Project, Env: coord.Env}
	if strings.HasPrefix(ref, "/") {
		segs, err := normalizeFolder(ref)
		if err != nil || len(segs) == 0 {
			return "${" + ref + "}"
		}
		target.Folder = segs[:len(segs)-1]
		target.Key = segs[len(segs)-1]
	} else {
		target.Folder = coord.Folder
		target.Key = ref
	}
	if target.validate() != nil {
		return "${" + ref + "}"
	}
	val, err := svc.store.GetSecretValue(ctx, target.backingName(), "", "")
	if err != nil || val.SecretString == nil {
		return "${" + ref + "}"
	}
	return svc.resolveReferences(ctx, target, *val.SecretString, depth-1)
}

// hierarchyStore is the optional structure backend a keyStore may implement to
// persist projects, environments, and empty folders that cannot be derived from
// secret names alone.
type hierarchyStore interface {
	ListHierarchy(ctx context.Context) ([]hierarchyProject, error)
	ListFolders(ctx context.Context, project, env string, folder []string) ([]string, error)
	CreateProject(ctx context.Context, slug, name string) error
	CreateEnvironment(ctx context.Context, project, slug, name string) error
	CreateFolder(ctx context.Context, project, env string, folder []string) error
}

type hierarchyProject struct {
	Project      string
	Name         string
	Environments []string
}

var errNoHierarchyStore = errors.New("hierarchy structure is not supported by this store")

// CreateProject registers a structure-only project so that empty projects show
// up in the UI before any secret is written under them.
func (svc *secretsService) CreateProject(ctx context.Context, slug, name string) error {
	if err := validateSegment("project", slug); err != nil {
		return err
	}
	if svc.hierarchy == nil {
		return errNoHierarchyStore
	}
	return svc.hierarchy.CreateProject(ctx, slug, strings.TrimSpace(name))
}

// CreateEnvironment registers a structure-only environment under a project.
func (svc *secretsService) CreateEnvironment(ctx context.Context, project, slug, name string) error {
	if err := validateSegment("project", project); err != nil {
		return err
	}
	if err := validateSegment("env", slug); err != nil {
		return err
	}
	if svc.hierarchy == nil {
		return errNoHierarchyStore
	}
	return svc.hierarchy.CreateEnvironment(ctx, project, slug, strings.TrimSpace(name))
}

// CreateFolder registers a structure-only (possibly empty) folder.
func (svc *secretsService) CreateFolder(ctx context.Context, project, env string, folder []string) error {
	if err := validateSegment("project", project); err != nil {
		return err
	}
	if err := validateSegment("env", env); err != nil {
		return err
	}
	for _, seg := range folder {
		if err := validateSegment("folder", seg); err != nil {
			return err
		}
	}
	if len(folder) == 0 {
		return errors.New("folder path is required")
	}
	if svc.hierarchy == nil {
		return errNoHierarchyStore
	}
	return svc.hierarchy.CreateFolder(ctx, project, env, folder)
}

// DescribeItem returns the full metadata projection for a single item.
func (svc *secretsService) DescribeItem(ctx context.Context, coord itemCoord) (itemDetail, error) {
	if err := coord.validate(); err != nil {
		return itemDetail{}, err
	}
	meta, err := svc.store.DescribeSecret(ctx, coord.backingName())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || isSecretNotFound(err) {
			return itemDetail{}, errItemNotFound
		}
		return itemDetail{}, err
	}
	return itemDetail{
		Project:           coord.Project,
		Env:               coord.Env,
		Path:              folderPath(coord.Folder),
		Key:               coord.Key,
		ARN:               meta.ARN,
		Description:       meta.Description,
		KMSKeyID:          meta.KMSKeyID,
		CurrentVersionID:  meta.CurrentVersionID,
		PreviousVersionID: meta.PreviousVersionID,
		CreatedAt:         meta.CreatedAt,
		UpdatedAt:         meta.LastChangedDate,
		DeletionDate:      meta.DeletedDate,
		Tags:              meta.Tags,
		PolicyDocument:    meta.PolicyDocument,
		RotationEnabled:   meta.RotationEnabled,
		RotationLambdaARN: meta.RotationLambdaARN,
		RotationDays:      meta.RotationDays,
		NextRotationDate:  meta.NextRotationDate,
	}, nil
}

// UpdateItemMetadata updates an item's description and/or KMS key without
// writing a new secret value.
func (svc *secretsService) UpdateItemMetadata(ctx context.Context, coord itemCoord, description, kmsKeyID string) error {
	if err := coord.validate(); err != nil {
		return err
	}
	_, _, err := svc.store.UpdateSecret(ctx, updateSecretRequest{
		SecretID:    coord.backingName(),
		Description: description,
		KMSKeyID:    strings.TrimSpace(kmsKeyID),
	})
	return mapItemErr(err)
}

// PromoteItemVersion moves the AWSCURRENT stage to versionID, demoting the
// previous current version to AWSPREVIOUS.
func (svc *secretsService) PromoteItemVersion(ctx context.Context, coord itemCoord, versionID string) error {
	if err := coord.validate(); err != nil {
		return err
	}
	if strings.TrimSpace(versionID) == "" {
		return errors.New("versionId is required")
	}
	_, err := svc.store.UpdateSecretVersionStage(ctx, coord.backingName(), currentVersionStage, strings.TrimSpace(versionID), "")
	return mapItemErr(err)
}

// TagItem adds or updates tags on an item.
func (svc *secretsService) TagItem(ctx context.Context, coord itemCoord, tags []secretTag) error {
	if err := coord.validate(); err != nil {
		return err
	}
	if len(tags) == 0 {
		return errors.New("at least one tag is required")
	}
	return mapItemErr(svc.store.TagSecret(ctx, coord.backingName(), tags))
}

// UntagItem removes tags from an item by key.
func (svc *secretsService) UntagItem(ctx context.Context, coord itemCoord, keys []string) error {
	if err := coord.validate(); err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("at least one tag key is required")
	}
	return mapItemErr(svc.store.UntagSecret(ctx, coord.backingName(), keys))
}

// GetItemPolicy returns the resource policy attached to an item.
func (svc *secretsService) GetItemPolicy(ctx context.Context, coord itemCoord) (string, error) {
	if err := coord.validate(); err != nil {
		return "", err
	}
	doc, err := svc.store.GetSecretResourcePolicy(ctx, coord.backingName())
	return doc, mapItemErr(err)
}

// PutItemPolicy attaches (or clears, when empty) a resource policy on an item.
func (svc *secretsService) PutItemPolicy(ctx context.Context, coord itemCoord, document string) error {
	if err := coord.validate(); err != nil {
		return err
	}
	return mapItemErr(svc.store.PutSecretResourcePolicy(ctx, coord.backingName(), document))
}

// ConfigureItemRotation enables or updates rotation configuration for an item.
func (svc *secretsService) ConfigureItemRotation(ctx context.Context, coord itemCoord, lambdaARN string, afterDays int, rotateImmediately bool) error {
	if err := coord.validate(); err != nil {
		return err
	}
	_, err := svc.store.RotateSecret(ctx, coord.backingName(), strings.TrimSpace(lambdaARN), afterDays, rotateImmediately, "")
	return mapItemErr(err)
}

// CancelItemRotation disables rotation for an item.
func (svc *secretsService) CancelItemRotation(ctx context.Context, coord itemCoord) error {
	if err := coord.validate(); err != nil {
		return err
	}
	_, err := svc.store.CancelRotateSecret(ctx, coord.backingName())
	return mapItemErr(err)
}

// mapItemErr normalizes store "not found" errors to errItemNotFound.
func mapItemErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) || isSecretNotFound(err) {
		return errItemNotFound
	}
	return err
}

func fmtHierarchyKey(parts ...string) string {
	return strings.Join(parts, "\x00")
}
