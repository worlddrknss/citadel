package postgres

import (
	"context"
	"sort"

	"github.com/worlddrknss/citadel/internal/store"
)

// ListHierarchy returns structure-only projects/environments for the caller.
func (s *Store) ListHierarchy(ctx context.Context) ([]store.HierarchyProject, error) {
	account := s.accountForContext(ctx)
	rows, err := s.db.QueryContext(ctx,
		`SELECT slug, name FROM sm_projects WHERE account_id=$1 ORDER BY slug`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bySlug := map[string]*store.HierarchyProject{}
	order := []string{}
	for rows.Next() {
		var slug, name string
		if err := rows.Scan(&slug, &name); err != nil {
			return nil, err
		}
		bySlug[slug] = &store.HierarchyProject{Project: slug, Name: name}
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
			p = &store.HierarchyProject{Project: project}
			bySlug[project] = p
			order = append(order, project)
		}
		p.Environments = append(p.Environments, slug)
	}
	if err := erows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(order)
	out := make([]store.HierarchyProject, 0, len(order))
	for _, slug := range order {
		out = append(out, *bySlug[slug])
	}
	return out, nil
}

// ListFolders returns immediate registered subfolders under the given path.
func (s *Store) ListFolders(ctx context.Context, project, env string, folder []string) ([]string, error) {
	account := s.accountForContext(ctx)
	prefix := store.FolderPath(folder)
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
		if child, ok := store.ImmediateChild(prefix, path); ok {
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
func (s *Store) CreateProject(ctx context.Context, slug, name string) error {
	account := s.accountForContext(ctx)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sm_projects (account_id, slug, name) VALUES ($1,$2,$3)
		 ON CONFLICT (account_id, slug) DO UPDATE SET name=CASE WHEN EXCLUDED.name <> '' THEN EXCLUDED.name ELSE sm_projects.name END`,
		account, slug, name)
	return err
}

// CreateEnvironment registers a structure-only environment under a project.
func (s *Store) CreateEnvironment(ctx context.Context, project, slug, name string) error {
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
func (s *Store) CreateFolder(ctx context.Context, project, env string, folder []string) error {
	account := s.accountForContext(ctx)
	if err := s.CreateEnvironment(ctx, project, env, ""); err != nil {
		return err
	}
	for i := 1; i <= len(folder); i++ {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO sm_folders (account_id, project_slug, env_slug, folder_path) VALUES ($1,$2,$3,$4)
			 ON CONFLICT (account_id, project_slug, env_slug, folder_path) DO NOTHING`,
			account, project, env, store.FolderPath(folder[:i])); err != nil {
			return err
		}
	}
	return nil
}

// RenameProject updates a project's display name.
func (s *Store) RenameProject(ctx context.Context, slug, newName string) error {
	account := s.accountForContext(ctx)
	_, err := s.db.ExecContext(ctx,
		`UPDATE sm_projects SET name=$3 WHERE account_id=$1 AND slug=$2`,
		account, slug, newName)
	return err
}

// RenameEnvironment updates an environment's display name.
func (s *Store) RenameEnvironment(ctx context.Context, project, slug, newName string) error {
	account := s.accountForContext(ctx)
	_, err := s.db.ExecContext(ctx,
		`UPDATE sm_environments SET name=$4 WHERE account_id=$1 AND project_slug=$2 AND slug=$3`,
		account, project, slug, newName)
	return err
}

// DeleteProject removes a structure-only project and its environments/folders.
func (s *Store) DeleteProject(ctx context.Context, slug string) error {
	account := s.accountForContext(ctx)
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM sm_folders WHERE account_id=$1 AND project_slug=$2`, account, slug); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM sm_environments WHERE account_id=$1 AND project_slug=$2`, account, slug); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM sm_projects WHERE account_id=$1 AND slug=$2`, account, slug)
	return err
}

// DeleteEnvironment removes a structure-only environment and its folders.
func (s *Store) DeleteEnvironment(ctx context.Context, project, slug string) error {
	account := s.accountForContext(ctx)
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM sm_folders WHERE account_id=$1 AND project_slug=$2 AND env_slug=$3`,
		account, project, slug); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM sm_environments WHERE account_id=$1 AND project_slug=$2 AND slug=$3`,
		account, project, slug)
	return err
}

// DeleteFolder removes a structure-only folder and any nested folders.
func (s *Store) DeleteFolder(ctx context.Context, project, env string, folder []string) error {
	account := s.accountForContext(ctx)
	prefix := store.FolderPath(folder)
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM sm_folders WHERE account_id=$1 AND project_slug=$2 AND env_slug=$3
		 AND (folder_path=$4 OR folder_path LIKE $5)`,
		account, project, env, prefix, prefix+"/%")
	return err
}
