package store

import (
	"encoding/json"
	"strings"
)

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
