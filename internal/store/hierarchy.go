package store

// Hierarchy STRUCTURE (projects, environments, and empty folders) is stored
// independently of secret VALUES so the native UI can model containers that do
// not yet hold any item. Item values continue to live in the AWS-compatible
// secrets store, keeping External Secrets Operator and the AWS SDK working
// unchanged.

import (
	"context"
	"strings"
)

// ImmediateChild reports the immediate child folder name of full when full is a
// strict descendant of prefix. prefix and full are normalized folder paths from
// FolderPath (e.g. "/" or "/a/b").
func ImmediateChild(prefix, full string) (string, bool) {
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

// FolderPath renders folder segments back into a canonical "/a/b" string. Root
// is rendered as "/".
func FolderPath(segs []string) string {
	if len(segs) == 0 {
		return "/"
	}
	return "/" + strings.Join(segs, "/")
}

// HierarchyStore is the structure backend that persists projects,
// environments, and empty folders that cannot be derived from secret names
// alone.
type HierarchyStore interface {
	ListHierarchy(ctx context.Context) ([]HierarchyProject, error)
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

type HierarchyProject struct {
	Project      string
	Name         string
	Environments []string
}

func FmtHierarchyKey(parts ...string) string {
	return strings.Join(parts, "\x00")
}
