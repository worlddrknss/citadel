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

// shadowName is the backing name of the object that would sit at a folder's own
// path — "d76riders/prod" for the folder d76riders/prod, as opposed to the
// "d76riders/prod/KEY" items inside it.
func shadowName(project, env string, folder []string) string {
	return strings.Join(append([]string{project, env}, folder...), "/")
}

// ListFolder returns the immediate subfolders, the items located directly at the
// requested project/env/folder path, and any object occupying the folder's own
// path.
//
// That last one exists because a backing secret can be named exactly like a
// folder. parseSecretName needs at least project/env/key, so an object named
// "d76riders/prod" decomposes into nothing and was dropped from this listing
// entirely: not a folder, not an item, invisible in the UI while still being
// perfectly readable through the Secrets Manager API. One such object fed
// d76riders' ExternalSecret for five days, holding a stale copy of the
// environment and quietly costing it EMERGENCY_MASTER_KEY, with nothing in the
// console to suggest it existed. Returned separately rather than mixed into
// items: it is not a key in this folder, it is a thing wearing the folder's name.
func (svc *secretsService) ListFolder(ctx context.Context, project, env string, folder []string) (folders []string, items []itemSummary, shadowed []itemSummary, err error) {
	if err = validateSegment("project", project); err != nil {
		return nil, nil, nil, err
	}
	if err = validateSegment("env", env); err != nil {
		return nil, nil, nil, err
	}
	secrets, err := svc.store.ListSecrets(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	items = make([]itemSummary, 0)
	shadowed = make([]itemSummary, 0)
	subfolders := map[string]struct{}{}
	wantShadow := shadowName(project, env, folder)
	for _, sec := range secrets {
		pi, ok := parseSecretName(sec.Name)
		if !ok {
			// Unparseable as an item. If it is wearing this folder's name, surface
			// it so it can be seen and deleted; otherwise it belongs to some other
			// folder and will be surfaced when that one is listed.
			if sec.Name == wantShadow {
				shadowed = append(shadowed, itemSummary{
					Project:      project,
					Env:          env,
					Path:         folderPath(folder),
					Key:          "",
					ARN:          sec.ARN,
					UpdatedAt:    sec.LastChangedDate.UTC(),
					DeletionDate: sec.DeletedDate,
				})
			}
			continue
		}
		if pi.Project != project || pi.Env != env {
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
	return folders, items, shadowed, nil
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
	_, items, _, err := svc.ListFolder(ctx, project, env, folder)
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

// NameShadowsFolder reports whether storing a secret under this exact name would
// shadow a folder that already holds items.
//
// The two shapes share a namespace: "d76riders/prod/MAPBOX_TOKEN" is an item, and
// "d76riders/prod" is the JSON projection of every item in that folder. The
// projection is only computed when no stored secret answers to that name, so a
// stored object at a folder's name silently replaces a live view with a frozen
// copy — and stays invisible in a UI that lists a folder's children.
func (svc *secretsService) NameShadowsFolder(ctx context.Context, name string) (bool, error) {
	parts := strings.Split(strings.Trim(strings.TrimSpace(name), "/"), "/")
	if len(parts) < 2 {
		return false, nil
	}
	project, env := parts[0], parts[1]
	folder := parts[2:]
	if validateSegment("project", project) != nil || validateSegment("env", env) != nil {
		return false, nil
	}
	for _, seg := range folder {
		if validateSegment("folder", seg) != nil {
			return false, nil
		}
	}
	_, items, _, err := svc.ListFolder(ctx, project, env, folder)
	if err != nil {
		return false, err
	}
	return len(items) > 0, nil
}

// DeleteShadowing removes the object occupying a folder's own name, which is
// otherwise unaddressable: itemCoord always appends a key, so no coordinate can
// name it. Used to clear objects created before NameShadowsFolder rejected them.
func (svc *secretsService) DeleteShadowing(ctx context.Context, project, env string, folder []string, recoveryWindowDays int, forceDelete bool) error {
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
	if _, err := svc.store.DeleteSecret(ctx, shadowName(project, env, folder), recoveryWindowDays, forceDelete); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errItemNotFound
		}
		return err
	}
	return nil
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
	RenameProject(ctx context.Context, slug, newName string) error
	RenameEnvironment(ctx context.Context, project, slug, newName string) error
	DeleteProject(ctx context.Context, slug string) error
	DeleteEnvironment(ctx context.Context, project, slug string) error
	DeleteFolder(ctx context.Context, project, env string, folder []string) error
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

// errContainerNotEmpty is returned when a structure delete is attempted on a
// project/environment/folder that still holds secret items.
var errContainerNotEmpty = errors.New("container still holds secrets; delete the secrets first")

// countSecrets counts backing secret items under a project, optionally scoped
// to an environment and a folder prefix.
func (svc *secretsService) countSecrets(ctx context.Context, project, env string, folder []string) (int, error) {
	secrets, err := svc.store.ListSecrets(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, sec := range secrets {
		pi, ok := parseSecretName(sec.Name)
		if !ok || pi.Project != project {
			continue
		}
		if env != "" && pi.Env != env {
			continue
		}
		if len(folder) > 0 && !folderHasPrefix(pi.Folder, folder) {
			continue
		}
		n++
	}
	return n, nil
}

// RenameProject updates a project's display name (the slug is immutable because
// it forms part of every backing secret name).
func (svc *secretsService) RenameProject(ctx context.Context, slug, newName string) error {
	if err := validateSegment("project", slug); err != nil {
		return err
	}
	if svc.hierarchy == nil {
		return errNoHierarchyStore
	}
	return svc.hierarchy.RenameProject(ctx, slug, strings.TrimSpace(newName))
}

// RenameEnvironment updates an environment's display name.
func (svc *secretsService) RenameEnvironment(ctx context.Context, project, slug, newName string) error {
	if err := validateSegment("project", project); err != nil {
		return err
	}
	if err := validateSegment("env", slug); err != nil {
		return err
	}
	if svc.hierarchy == nil {
		return errNoHierarchyStore
	}
	return svc.hierarchy.RenameEnvironment(ctx, project, slug, strings.TrimSpace(newName))
}

// DeleteProject removes a structure-only project. It refuses while any backing
// secret still exists under the project.
func (svc *secretsService) DeleteProject(ctx context.Context, slug string) error {
	if err := validateSegment("project", slug); err != nil {
		return err
	}
	if svc.hierarchy == nil {
		return errNoHierarchyStore
	}
	n, err := svc.countSecrets(ctx, slug, "", nil)
	if err != nil {
		return err
	}
	if n > 0 {
		return errContainerNotEmpty
	}
	return svc.hierarchy.DeleteProject(ctx, slug)
}

// DeleteEnvironment removes a structure-only environment. It refuses while any
// backing secret still exists under the project/environment.
func (svc *secretsService) DeleteEnvironment(ctx context.Context, project, slug string) error {
	if err := validateSegment("project", project); err != nil {
		return err
	}
	if err := validateSegment("env", slug); err != nil {
		return err
	}
	if svc.hierarchy == nil {
		return errNoHierarchyStore
	}
	n, err := svc.countSecrets(ctx, project, slug, nil)
	if err != nil {
		return err
	}
	if n > 0 {
		return errContainerNotEmpty
	}
	return svc.hierarchy.DeleteEnvironment(ctx, project, slug)
}

// DeleteFolder removes a structure-only folder (and its nested registrations).
// It refuses while any backing secret still exists at or below the folder.
func (svc *secretsService) DeleteFolder(ctx context.Context, project, env string, folder []string) error {
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
	n, err := svc.countSecrets(ctx, project, env, folder)
	if err != nil {
		return err
	}
	if n > 0 {
		return errContainerNotEmpty
	}
	return svc.hierarchy.DeleteFolder(ctx, project, env, folder)
}

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

// UpdateItemMetadata updates an item's description and/or KMS key.
//
// Changing the KMS key requires re-encrypting the stored value under the new
// key: a secret's ciphertext is sealed with its key's master key and is later
// decrypted using whatever key the metadata points at. Moving only the key
// pointer would leave the ciphertext sealed with the old master key and render
// it undecryptable. When the key changes we therefore re-supply the current
// value so UpdateSecret writes a fresh version encrypted under the new key.
func (svc *secretsService) UpdateItemMetadata(ctx context.Context, coord itemCoord, description, kmsKeyID string) error {
	if err := coord.validate(); err != nil {
		return err
	}
	name := coord.backingName()
	desiredKey := strings.TrimSpace(kmsKeyID)
	req := updateSecretRequest{
		SecretID:    name,
		Description: description,
		KMSKeyID:    desiredKey,
	}
	if desiredKey != "" {
		meta, err := svc.store.DescribeSecret(ctx, name)
		if err != nil {
			return mapItemErr(err)
		}
		if desiredKey != meta.KMSKeyID {
			if err := svc.attachCurrentValue(ctx, coord, &req); err != nil {
				return err
			}
		}
	}
	_, _, err := svc.store.UpdateSecret(ctx, req)
	return mapItemErr(err)
}

// ReKeyItem re-encrypts a single item's current value under newKMSKeyID,
// writing a new version. It is the safe primitive behind "rotate KMS key".
func (svc *secretsService) ReKeyItem(ctx context.Context, coord itemCoord, newKMSKeyID string) error {
	if err := coord.validate(); err != nil {
		return err
	}
	newKey := strings.TrimSpace(newKMSKeyID)
	if newKey == "" {
		return errors.New("kmsKeyId is required")
	}
	req := updateSecretRequest{SecretID: coord.backingName(), KMSKeyID: newKey}
	if err := svc.attachCurrentValue(ctx, coord, &req); err != nil {
		return err
	}
	_, _, err := svc.store.UpdateSecret(ctx, req)
	return mapItemErr(err)
}

// ReKeyEnvironment re-encrypts every active item in project/env under
// newKMSKeyID. It returns the number rotated and the keys that failed, so a
// partial failure does not abort the whole batch.
func (svc *secretsService) ReKeyEnvironment(ctx context.Context, project, env, newKMSKeyID string) (int, []string, error) {
	if err := validateSegment("project", project); err != nil {
		return 0, nil, err
	}
	if err := validateSegment("env", env); err != nil {
		return 0, nil, err
	}
	if strings.TrimSpace(newKMSKeyID) == "" {
		return 0, nil, errors.New("kmsKeyId is required")
	}
	secrets, err := svc.store.ListSecrets(ctx)
	if err != nil {
		return 0, nil, err
	}
	rekeyed := 0
	failed := []string{}
	for _, sec := range secrets {
		if sec.DeletedDate != nil {
			continue
		}
		pi, ok := parseSecretName(sec.Name)
		if !ok || pi.Project != project || pi.Env != env {
			continue
		}
		coord := itemCoord{Project: pi.Project, Env: pi.Env, Folder: pi.Folder, Key: pi.Key}
		if err := svc.ReKeyItem(ctx, coord, newKMSKeyID); err != nil {
			failed = append(failed, pi.Key)
			continue
		}
		rekeyed++
	}
	return rekeyed, failed, nil
}

// attachCurrentValue reveals the item's current value and copies it into req so
// the subsequent UpdateSecret writes a new, re-encrypted version. It refuses to
// proceed when there is no value to re-encrypt, since that would let the caller
// move the key pointer without re-sealing the ciphertext.
func (svc *secretsService) attachCurrentValue(ctx context.Context, coord itemCoord, req *updateSecretRequest) error {
	current, err := svc.RevealItem(ctx, coord, "", "")
	if err != nil {
		return mapItemErr(err)
	}
	if current.SecretBinary != "" {
		req.SecretBinary = current.SecretBinary
	} else if current.SecretString != nil {
		req.SecretString = *current.SecretString
	}
	if req.SecretString == "" && req.SecretBinary == "" {
		return errors.New("cannot re-key an empty secret value; store a value first")
	}
	return nil
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
