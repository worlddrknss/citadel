package memory

import (
	"context"
	"sort"
	"strings"

	"github.com/worlddrknss/citadel/internal/store"
)

// memProject is the in-memory representation of one project's structure.
type memProject struct {
	account string
	slug    string
	name    string
	envs    map[string]string              // env slug -> display name
	folders map[string]map[string]struct{} // env slug -> set of folder paths ("/a/b")
}

func (s *Store) hierProjectsLocked() map[string]*memProject {
	if s.hier == nil {
		s.hier = map[string]*memProject{}
	}
	return s.hier
}

// ListHierarchy returns the structure-only projects/environments for the caller.
func (s *Store) ListHierarchy(ctx context.Context) ([]store.HierarchyProject, error) {
	account := s.accountForContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]store.HierarchyProject, 0)
	for _, p := range s.hierProjectsLocked() {
		if p.account != account {
			continue
		}
		envs := make([]string, 0, len(p.envs))
		for e := range p.envs {
			envs = append(envs, e)
		}
		sort.Strings(envs)
		out = append(out, store.HierarchyProject{Project: p.slug, Name: p.name, Environments: envs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Project < out[j].Project })
	return out, nil
}

// ListFolders returns the immediate registered subfolders directly under the
// requested project/env/folder path.
func (s *Store) ListFolders(ctx context.Context, project, env string, folder []string) ([]string, error) {
	account := s.accountForContext(ctx)
	prefix := store.FolderPath(folder)
	s.mu.Lock()
	defer s.mu.Unlock()
	key := store.FmtHierarchyKey(account, project)
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
		child, ok := store.ImmediateChild(prefix, path)
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
func (s *Store) CreateProject(ctx context.Context, slug, name string) error {
	account := s.accountForContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	key := store.FmtHierarchyKey(account, slug)
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
func (s *Store) CreateEnvironment(ctx context.Context, project, slug, name string) error {
	account := s.accountForContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	key := store.FmtHierarchyKey(account, project)
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
func (s *Store) CreateFolder(ctx context.Context, project, env string, folder []string) error {
	account := s.accountForContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	key := store.FmtHierarchyKey(account, project)
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
		p.folders[env][store.FolderPath(folder[:i])] = struct{}{}
	}
	return nil
}

// RenameProject updates a project's display name.
func (s *Store) RenameProject(ctx context.Context, slug, newName string) error {
	account := s.accountForContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.hierProjectsLocked()[store.FmtHierarchyKey(account, slug)]; ok {
		p.name = newName
	}
	return nil
}

// RenameEnvironment updates an environment's display name.
func (s *Store) RenameEnvironment(ctx context.Context, project, slug, newName string) error {
	account := s.accountForContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.hierProjectsLocked()[store.FmtHierarchyKey(account, project)]; ok {
		if _, ok := p.envs[slug]; ok {
			p.envs[slug] = newName
		}
	}
	return nil
}

// DeleteProject removes a structure-only project and all of its nested
// environments and folders.
func (s *Store) DeleteProject(ctx context.Context, slug string) error {
	account := s.accountForContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.hierProjectsLocked(), store.FmtHierarchyKey(account, slug))
	return nil
}

// DeleteEnvironment removes a structure-only environment and its folders.
func (s *Store) DeleteEnvironment(ctx context.Context, project, slug string) error {
	account := s.accountForContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.hierProjectsLocked()[store.FmtHierarchyKey(account, project)]; ok {
		delete(p.envs, slug)
		delete(p.folders, slug)
	}
	return nil
}

// DeleteFolder removes a structure-only folder and any nested folders.
func (s *Store) DeleteFolder(ctx context.Context, project, env string, folder []string) error {
	account := s.accountForContext(ctx)
	prefix := store.FolderPath(folder)
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.hierProjectsLocked()[store.FmtHierarchyKey(account, project)]
	if !ok {
		return nil
	}
	paths, ok := p.folders[env]
	if !ok {
		return nil
	}
	for path := range paths {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			delete(paths, path)
		}
	}
	return nil
}
