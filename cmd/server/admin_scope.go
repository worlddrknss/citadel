package main

import "strings"

func uiCanEdit(session *uiSession) bool {
	return session != nil && uiRoleAtLeast(session.Role, "editor")
}

func uiCanAdmin(session *uiSession) bool {
	return session != nil && uiRoleAtLeast(session.Role, "admin")
}

func secretVisibleToSession(session *uiSession, secretName string) bool {
	if session == nil || uiCanAdmin(session) || len(session.Tenants) == 0 {
		return true
	}
	tenant := tenantFromSecretName(secretName)
	return containsFold(session.Tenants, tenant)
}

func keyVisibleToSession(session *uiSession, keyID string, aliases []kmsAlias) bool {
	if session == nil || uiCanAdmin(session) || len(session.Tenants) == 0 {
		return true
	}
	for _, alias := range aliases {
		if alias.TargetKeyID != keyID {
			continue
		}
		if containsFold(session.Tenants, tenantFromAlias(alias.AliasName)) {
			return true
		}
	}
	return false
}

func tenantFromSecretName(name string) string {
	trimmed := strings.Trim(strings.TrimSpace(name), "/")
	if trimmed == "" {
		return ""
	}
	parts := strings.Split(trimmed, "/")
	return strings.ToLower(strings.TrimSpace(parts[0]))
}

func tenantFromAlias(alias string) string {
	alias = strings.TrimPrefix(strings.TrimSpace(alias), "alias/")
	if alias == "" {
		return ""
	}
	parts := strings.Split(alias, "/")
	return strings.ToLower(strings.TrimSpace(parts[0]))
}

func containsFold(values []string, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	for _, value := range values {
		if strings.ToLower(strings.TrimSpace(value)) == target {
			return true
		}
	}
	return false
}