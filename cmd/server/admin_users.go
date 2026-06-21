package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

// errUIUserNotFound is returned when a UI user lookup or delete targets an
// unknown username.
var errUIUserNotFound = errors.New("ui user not found")

// ListUIUsers returns the admin-console users persisted in the database.
func (s *dbStore) ListUIUsers(ctx context.Context) ([]uiUserConfig, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT username, password_hash, role, display_name, accounts_json FROM ui_users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []uiUserConfig
	for rows.Next() {
		var (
			user         uiUserConfig
			accountsJSON string
		)
		if err := rows.Scan(&user.Username, &user.PasswordHash, &user.Role, &user.DisplayName, &accountsJSON); err != nil {
			return nil, err
		}
		user.Accounts = decodeAccountsJSON(accountsJSON)
		users = append(users, user)
	}
	return users, rows.Err()
}

// UpsertUIUser inserts or updates an admin-console user. The PasswordHash field
// must already contain an Argon2id hash; plaintext passwords are never stored.
func (s *dbStore) UpsertUIUser(ctx context.Context, user uiUserConfig) error {
	username := strings.TrimSpace(user.Username)
	if username == "" {
		return errors.New("ui user requires a username")
	}
	if strings.TrimSpace(user.PasswordHash) == "" {
		return errors.New("ui user requires a password hash")
	}
	accountsJSON, err := encodeAccountsJSON(user.Accounts)
	if err != nil {
		return err
	}
	const q = `INSERT INTO ui_users (username, password_hash, role, display_name, accounts_json, updated_at)
VALUES ($1, $2, $3, $4, $5, NOW())
ON CONFLICT (username) DO UPDATE SET
	password_hash = EXCLUDED.password_hash,
	role = EXCLUDED.role,
	display_name = EXCLUDED.display_name,
	accounts_json = EXCLUDED.accounts_json,
	updated_at = NOW()`
	_, err = s.db.ExecContext(ctx, q, username, user.PasswordHash, normalizeUIRole(user.Role), user.DisplayName, accountsJSON)
	return err
}

// DeleteUIUser removes an admin-console user.
func (s *dbStore) DeleteUIUser(ctx context.Context, username string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM ui_users WHERE username = $1`, strings.TrimSpace(username))
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errUIUserNotFound
	}
	return nil
}

// ListUIUsers returns admin-console users held in memory.
func (s *inMemoryStore) ListUIUsers(_ context.Context) ([]uiUserConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	users := make([]uiUserConfig, 0, len(s.uiUsers))
	for _, user := range s.uiUsers {
		users = append(users, user)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	return users, nil
}

// UpsertUIUser stores an admin-console user in memory.
func (s *inMemoryStore) UpsertUIUser(_ context.Context, user uiUserConfig) error {
	username := strings.TrimSpace(user.Username)
	if username == "" {
		return errors.New("ui user requires a username")
	}
	if strings.TrimSpace(user.PasswordHash) == "" {
		return errors.New("ui user requires a password hash")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uiUsers == nil {
		s.uiUsers = map[string]uiUserConfig{}
	}
	user.Username = username
	user.Role = normalizeUIRole(user.Role)
	s.uiUsers[username] = user
	return nil
}

// DeleteUIUser removes an admin-console user from memory.
func (s *inMemoryStore) DeleteUIUser(_ context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	username = strings.TrimSpace(username)
	if _, ok := s.uiUsers[username]; !ok {
		return errUIUserNotFound
	}
	delete(s.uiUsers, username)
	return nil
}

func decodeAccountsJSON(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var accounts []string
	if err := json.Unmarshal([]byte(raw), &accounts); err != nil {
		return nil
	}
	return normalizeAccounts(accounts)
}

func encodeAccountsJSON(accounts []string) (string, error) {
	if len(accounts) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(normalizeAccounts(accounts))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// mergeDBUIUsers loads admin-console users from the store and merges them into
// the provided base map (typically env-configured users). Database users take
// precedence so operators can manage accounts without a redeploy. Env users
// with a plaintext password are seeded into the database (hashed) on first run
// when they are not already present.
func mergeDBUIUsers(ctx context.Context, store keyStore, base map[string]uiUserConfig) (map[string]uiUserConfig, error) {
	merged := map[string]uiUserConfig{}
	for name, user := range base {
		merged[name] = user
	}

	dbUsers, err := store.ListUIUsers(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrConnDone) {
			return merged, nil
		}
		return merged, err
	}
	for _, user := range dbUsers {
		merged[user.Username] = user
	}

	// Seed env-configured users into the database (hashed) so they persist and
	// can be managed centrally. Only do this for the dbStore.
	if _, isDB := store.(*dbStore); isDB {
		for name, user := range base {
			if _, exists := merged[name]; exists {
				if _, inDB := findUser(dbUsers, name); inDB {
					continue
				}
			}
			hash := strings.TrimSpace(user.PasswordHash)
			if hash == "" {
				if strings.TrimSpace(user.Password) == "" {
					continue
				}
				h, err := hashPassword(user.Password)
				if err != nil {
					return merged, err
				}
				hash = h
			}
			seeded := user
			seeded.PasswordHash = hash
			seeded.Password = ""
			if err := store.UpsertUIUser(ctx, seeded); err != nil {
				return merged, err
			}
			merged[name] = seeded
		}
	}

	return merged, nil
}

func findUser(users []uiUserConfig, username string) (uiUserConfig, bool) {
	for _, user := range users {
		if user.Username == username {
			return user, true
		}
	}
	return uiUserConfig{}, false
}
