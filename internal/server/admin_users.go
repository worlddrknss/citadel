package server

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/postgres"
)

// mergeDBUIUsers loads admin-console users from the store and merges them into
// the provided base map (typically env-configured users). Database users take
// precedence so operators can manage accounts without a redeploy. Env users
// with a plaintext password are seeded into the database (hashed) on first run
// when they are not already present.
func mergeDBUIUsers(ctx context.Context, st store.Store, base map[string]store.UIUser) (map[string]store.UIUser, error) {
	merged := map[string]store.UIUser{}
	for name, user := range base {
		merged[name] = user
	}

	dbUsers, err := st.ListUIUsers(ctx)
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
	// can be managed centrally. Only do this for the PostgreSQL store.
	if _, isDB := st.(*postgres.Store); isDB {
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
				h, err := cryptoutil.HashPassword(user.Password)
				if err != nil {
					return merged, err
				}
				hash = h
			}
			seeded := user
			seeded.PasswordHash = hash
			seeded.Password = ""
			if err := st.UpsertUIUser(ctx, seeded); err != nil {
				return merged, err
			}
			merged[name] = seeded
		}
	}

	return merged, nil
}

func findUser(users []store.UIUser, username string) (store.UIUser, bool) {
	for _, user := range users {
		if user.Username == username {
			return user, true
		}
	}
	return store.UIUser{}, false
}
