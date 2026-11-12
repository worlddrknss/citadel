package store

import (
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
