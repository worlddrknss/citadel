package main

import (
	"context"
	"sort"
	"strings"
)

// This file implements the hierarchyStore interface (see secrets_service.go) on
// both backends. Hierarchy STRUCTURE — projects, environments, and empty
// folders — is stored independently of secret VALUES so the native UI can model
// containers that do not yet hold any item. Item values continue to live in the
// AWS-compatible secrets store, keeping External Secrets Operator and the AWS
// SDK working unchanged.

// memProject is the in-memory representation of one project's structure.
type memProject struct {
	account string
	slug    string
	name    string
	envs    map[string]string              // env slug -> display name
	folders map[string]map[string]struct{} // env slug -> set of folder paths ("/a/b")
}

func (s *inMemoryStore) hierProjectsLocked() map[string]*memProject {
	if s.hier == nil {
		s.hier = map[string]*memProject{}
	}
	return s.hier
}

// ListHierarchy returns the structure-only projects/environments for the caller.
func (s *inMemoryStore) ListHierarchy(ctx context.Context) ([]hierarchyProject, error) {
	account := s.accountForContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]hierarchyProject, 0)
	for _, p := range s.hierProjectsLocked() {
		if p.account != account {
			continue
		}
		envs := make([]string, 0, len(p.envs))
		for e := range p.envs {
			envs = append(envs, e)
		}
		sort.Strings(envs)
		out = append(out, hierarchyProject{Project: p.slug, Name: p.name, Environments: envs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Project < out[j].Project })
	return out, nil
}

// ListFolders returns the immediate registered subfolders directly under the
// requested project/env/folder path.
func (s *inMemoryStore) ListFolders(ctx context.Context, project, env string, folder []string) ([]string, error) {
	account := s.accountForContext(ctx)
	prefix := folderPath(folder)
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fmtHierarchyKey(account, project)
	p, ok := s.hierProjectsLocked()[key]
	if !ok {
		return nil, nil
	}
	paths, ok := p.folders[env]
	if !ok {
		return nil, nil
	}
	subSet := map[string]struct{}{}
	for path := range paths {
		child, ok := immediateChild(prefix, path)
		if ok {
			subSet[child] = struct{}{}
		}
	}
	out := make([]string, 0, len(subSet))
	for c := range subSet {
		out = append(out, c)
	}
	sort.Strings(out)
	return out, nil
}

// CreateProject registers a structure-only project for the caller's account.
func (s *inMemoryStore) CreateProject(ctx context.Context, slug, name string) error {
	account := s.accountForContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fmtHierarchyKey(account, slug)
	projects := s.hierProjectsLocked()
	if p, ok := projects[key]; ok {
		if name != "" {
			p.name = name
		}
		return nil
	}
	projects[key] = &memProject{
		account: account,
		slug:    slug,
		name:    name,
		envs:    map[string]string{},
		folders: map[string]map[string]struct{}{},
	}
	return nil
}

// CreateEnvironment registers a structure-only environment under a project,
// implicitly creating the project if needed.
func (s *inMemoryStore) CreateEnvironment(ctx context.Context, project, slug, name string) error {
	account := s.accountForContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fmtHierarchyKey(account, project)
	projects := s.hierProjectsLocked()
	p, ok := projects[key]
	if !ok {
		p = &memProject{
			account: account,
			slug:    project,
			envs:    map[string]string{},
			folders: map[string]map[string]struct{}{},
		}
		projects[key] = p
	}
	p.envs[slug] = name
	return nil
}

// CreateFolder registers a structure-only folder (and all of its parents),
// implicitly creating the project and environment if needed.
func (s *inMemoryStore) CreateFolder(ctx context.Context, project, env string, folder []string) error {
	account := s.accountForContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fmtHierarchyKey(account, project)
	projects := s.hierProjectsLocked()
	p, ok := projects[key]
	if !ok {
		p = &memProject{
			account: account,
			slug:    project,
			envs:    map[string]string{},
			folders: map[string]map[string]struct{}{},
		}
		projects[key] = p
	}
	if _, ok := p.envs[env]; !ok {
		p.envs[env] = ""
	}
	if p.folders[env] == nil {
		p.folders[env] = map[string]struct{}{}
	}
	for i := 1; i <= len(folder); i++ {
		p.folders[env][folderPath(folder[:i])] = struct{}{}
	}
	return nil
}

// immediateChild reports the immediate child folder name of full when full is a
// strict descendant of prefix. prefix and full are normalized folder paths from
// folderPath (e.g. "/" or "/a/b").
func immediateChild(prefix, full string) (string, bool) {
	if prefix == "/" {
		rest := strings.TrimPrefix(full, "/")
		if rest == "" {
			return "", false
		}
		first := rest
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			first = rest[:i]
		}
		return first, true
	}
	if !strings.HasPrefix(full, prefix+"/") {
		return "", false
	}
	rest := strings.TrimPrefix(full, prefix+"/")
	if rest == "" {
		return "", false
	}
	first := rest
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		first = rest[:i]
	}
	return first, true
}

// ---- dbStore (Postgres) implementation ----

// ListHierarchy returns structure-only projects/environments for the caller.
func (s *dbStore) ListHierarchy(ctx context.Context) ([]hierarchyProject, error) {
	account := s.accountForContext(ctx)
	rows, err := s.db.QueryContext(ctx,
		`SELECT slug, name FROM sm_projects WHERE account_id=$1 ORDER BY slug`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bySlug := map[string]*hierarchyProject{}
	order := []string{}
	for rows.Next() {
		var slug, name string
		if err := rows.Scan(&slug, &name); err != nil {
			return nil, err
		}
		bySlug[slug] = &hierarchyProject{Project: slug, Name: name}
		order = append(order, slug)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	erows, err := s.db.QueryContext(ctx,
		`SELECT project_slug, slug FROM sm_environments WHERE account_id=$1 ORDER BY project_slug, slug`, account)
	if err != nil {
		return nil, err
	}
	defer erows.Close()
	for erows.Next() {
		var project, slug string
		if err := erows.Scan(&project, &slug); err != nil {
			return nil, err
		}
		p, ok := bySlug[project]
		if !ok {
			p = &hierarchyProject{Project: project}
			bySlug[project] = p
			order = append(order, project)
		}
		p.Environments = append(p.Environments, slug)
	}
	if err := erows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(order)
	out := make([]hierarchyProject, 0, len(order))
	for _, slug := range order {
		out = append(out, *bySlug[slug])
	}
	return out, nil
}

// ListFolders returns immediate registered subfolders under the given path.
func (s *dbStore) ListFolders(ctx context.Context, project, env string, folder []string) ([]string, error) {
	account := s.accountForContext(ctx)
	prefix := folderPath(folder)
	rows, err := s.db.QueryContext(ctx,
		`SELECT folder_path FROM sm_folders WHERE account_id=$1 AND project_slug=$2 AND env_slug=$3`,
		account, project, env)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	subSet := map[string]struct{}{}
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			return nil, err
		}
		if child, ok := immediateChild(prefix, path); ok {
			subSet[child] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(subSet))
	for c := range subSet {
		out = append(out, c)
	}
	sort.Strings(out)
	return out, nil
}

// CreateProject registers a structure-only project for the caller's account.
func (s *dbStore) CreateProject(ctx context.Context, slug, name string) error {
	account := s.accountForContext(ctx)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sm_projects (account_id, slug, name) VALUES ($1,$2,$3)
		 ON CONFLICT (account_id, slug) DO UPDATE SET name=CASE WHEN EXCLUDED.name <> '' THEN EXCLUDED.name ELSE sm_projects.name END`,
		account, slug, name)
	return err
}

// CreateEnvironment registers a structure-only environment under a project.
func (s *dbStore) CreateEnvironment(ctx context.Context, project, slug, name string) error {
	account := s.accountForContext(ctx)
	if err := s.CreateProject(ctx, project, ""); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sm_environments (account_id, project_slug, slug, name) VALUES ($1,$2,$3,$4)
		 ON CONFLICT (account_id, project_slug, slug) DO UPDATE SET name=CASE WHEN EXCLUDED.name <> '' THEN EXCLUDED.name ELSE sm_environments.name END`,
		account, project, slug, name)
	return err
}

// CreateFolder registers a structure-only folder (and all of its parents).
func (s *dbStore) CreateFolder(ctx context.Context, project, env string, folder []string) error {
	account := s.accountForContext(ctx)
	if err := s.CreateEnvironment(ctx, project, env, ""); err != nil {
		return err
	}
	for i := 1; i <= len(folder); i++ {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO sm_folders (account_id, project_slug, env_slug, folder_path) VALUES ($1,$2,$3,$4)
			 ON CONFLICT (account_id, project_slug, env_slug, folder_path) DO NOTHING`,
			account, project, env, folderPath(folder[:i])); err != nil {
			return err
		}
	}
	return nil
}
