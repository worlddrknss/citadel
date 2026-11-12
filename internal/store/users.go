package store

import (
	"encoding/json"
	"strings"
)

type UIUser struct {
	Username     string   `json:"username"`
	Password     string   `json:"password"`
	PasswordHash string   `json:"passwordHash"`
	Role         string   `json:"role"`
	DisplayName  string   `json:"displayName"`
	Accounts     []string `json:"accounts"`
}

func NormalizeUIRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin", "editor", "viewer":
		return strings.ToLower(strings.TrimSpace(role))
	default:
		return "viewer"
	}
}

func NormalizeAccounts(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

// UnmarshalJSON accepts both the current "accounts" key and the legacy "tenants"
// key so previously persisted user configuration (including SOPS-encrypted env
// JSON) keeps working after the tenant->account rename.
func (u *UIUser) UnmarshalJSON(data []byte) error {
	type alias UIUser
	aux := struct {
		*alias
		LegacyTenants []string `json:"tenants"`
	}{alias: (*alias)(u)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if len(u.Accounts) == 0 && len(aux.LegacyTenants) > 0 {
		u.Accounts = aux.LegacyTenants
	}
	return nil
}

// storedCredential returns the secret used to verify a login attempt. A
// password hash is preferred; the plaintext Password field is only a
// fallback for legacy/env-configured users.
func (u UIUser) StoredCredential() string {
	if strings.TrimSpace(u.PasswordHash) != "" {
		return u.PasswordHash
	}
	return u.Password
}
