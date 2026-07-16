package main

import (
	"context"
	"testing"
)

// TestHierarchyEmptyFoldersAndProjects verifies the P3 structure store: empty
// projects, environments, and folders are persisted independently of secret
// values and surface through the secrets service, scoped per account.
func TestHierarchyEmptyFoldersAndProjects(t *testing.T) {
	store := newTenantTestStore()
	svc := newSecretsService(store)

	const acctA = "111111111111"
	const acctB = "222222222222"
	ctxA := withCallerAccount(context.Background(), acctA)
	ctxB := withCallerAccount(context.Background(), acctB)

	// Register an empty project + environment + nested folder for account A.
	if err := svc.CreateProject(ctxA, "payments", "Payments"); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if err := svc.CreateEnvironment(ctxA, "payments", "prod", "Production"); err != nil {
		t.Fatalf("CreateEnvironment: %v", err)
	}
	if err := svc.CreateFolder(ctxA, "payments", "prod", []string{"db", "primary"}); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	// Project shows up even with zero secrets.
	projects, err := svc.ListProjects(ctxA)
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(projects) != 1 || projects[0].Slug != "payments" {
		t.Fatalf("expected single payments project, got %+v", projects)
	}
	if len(projects[0].Environments) != 1 || projects[0].Environments[0] != "prod" {
		t.Fatalf("expected prod env, got %+v", projects[0].Environments)
	}

	// Root folder listing exposes the empty "db" subfolder.
	folders, items, _, err := svc.ListFolder(ctxA, "payments", "prod", nil)
	if err != nil {
		t.Fatalf("ListFolder root: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected no items at root, got %+v", items)
	}
	if len(folders) != 1 || folders[0] != "db" {
		t.Fatalf("expected db subfolder, got %+v", folders)
	}

	// Nested listing exposes the empty "primary" subfolder.
	folders, _, _, err = svc.ListFolder(ctxA, "payments", "prod", []string{"db"})
	if err != nil {
		t.Fatalf("ListFolder db: %v", err)
	}
	if len(folders) != 1 || folders[0] != "primary" {
		t.Fatalf("expected primary subfolder, got %+v", folders)
	}

	// Account B sees none of account A's structure.
	projectsB, err := svc.ListProjects(ctxB)
	if err != nil {
		t.Fatalf("ListProjects B: %v", err)
	}
	if len(projectsB) != 0 {
		t.Fatalf("expected account B to see no projects, got %+v", projectsB)
	}
}
