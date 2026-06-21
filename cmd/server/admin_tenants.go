package main

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
)

var errUITenantNotFound = errors.New("ui tenant not found")

func normalizeTenantName(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func (s *dbStore) ListUITenants(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT tenant FROM ui_tenants ORDER BY tenant`)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var tenants []string
	for rows.Next() {
		var tenant string
		if err := rows.Scan(&tenant); err != nil {
			return nil, err
		}
		tenant = normalizeTenantName(tenant)
		if tenant != "" {
			tenants = append(tenants, tenant)
		}
	}
	return tenants, rows.Err()
}

func (s *dbStore) UpsertUITenant(ctx context.Context, tenant string) error {
	tenant = normalizeTenantName(tenant)
	if tenant == "" {
		return errors.New("tenant is required")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO ui_tenants (tenant, updated_at) VALUES ($1, NOW()) ON CONFLICT (tenant) DO UPDATE SET updated_at = NOW()`, tenant)
	return err
}

func (s *dbStore) DeleteUITenant(ctx context.Context, tenant string) error {
	tenant = normalizeTenantName(tenant)
	if tenant == "" {
		return errors.New("tenant is required")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM ui_tenants WHERE tenant = $1`, tenant)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errUITenantNotFound
	}
	return nil
}

func (s *inMemoryStore) ListUITenants(_ context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uiTenants == nil {
		s.uiTenants = map[string]struct{}{}
	}
	for _, user := range s.uiUsers {
		for _, tenant := range user.Tenants {
			tenant = normalizeTenantName(tenant)
			if tenant != "" {
				s.uiTenants[tenant] = struct{}{}
			}
		}
	}
	tenants := make([]string, 0, len(s.uiTenants))
	for tenant := range s.uiTenants {
		tenants = append(tenants, tenant)
	}
	sort.Strings(tenants)
	return tenants, nil
}

func (s *inMemoryStore) UpsertUITenant(_ context.Context, tenant string) error {
	tenant = normalizeTenantName(tenant)
	if tenant == "" {
		return errors.New("tenant is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uiTenants == nil {
		s.uiTenants = map[string]struct{}{}
	}
	s.uiTenants[tenant] = struct{}{}
	return nil
}

func (s *inMemoryStore) DeleteUITenant(_ context.Context, tenant string) error {
	tenant = normalizeTenantName(tenant)
	if tenant == "" {
		return errors.New("tenant is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uiTenants == nil {
		s.uiTenants = map[string]struct{}{}
	}
	if _, ok := s.uiTenants[tenant]; !ok {
		return errUITenantNotFound
	}
	delete(s.uiTenants, tenant)
	return nil
}
