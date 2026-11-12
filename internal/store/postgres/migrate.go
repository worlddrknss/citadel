package postgres

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Schema migrations.
//
// The schema is defined by the versioned SQL files in migrations/, embedded
// into the binary and applied in version order by Migrate. Each file is named
// NNNN_description.sql and runs in its own transaction together with the
// schema_migrations row that records it, so a migration is either fully
// applied and recorded or not applied at all.
//
// Concurrent replicas starting against the same database serialize on a
// Postgres session-level advisory lock, so exactly one of them applies any
// pending migration and the others then find it already recorded.
//
// Databases created before versioned migrations existed have the schema but
// no schema_migrations table. 0001_initial is the startup DDL those databases
// were built with, verbatim, and it is idempotent, so for them it is simply
// run once more (bringing any older layout up to date, exactly as the startup
// DDL did on every boot) and recorded. Migrations after 0001 do not need to be
// idempotent.

//go:embed migrations/*.sql
var migrationFiles embed.FS

// migrationLockKey is the pg_advisory_lock key guarding Migrate. It is an
// arbitrary constant ("cita" in ASCII) shared by every Citadel replica.
const migrationLockKey int64 = 0x63697461

type migration struct {
	version int64
	name    string
	sql     string
}

// loadMigrations returns the embedded migrations sorted by version.
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return nil, err
	}
	var out []migration
	seen := map[int64]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".sql")
		num, desc, ok := strings.Cut(base, "_")
		if !ok || desc == "" {
			return nil, fmt.Errorf("migration %q: want NNNN_description.sql", e.Name())
		}
		version, err := strconv.ParseInt(num, 10, 64)
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("migration %q: bad version", e.Name())
		}
		if prev, dup := seen[version]; dup {
			return nil, fmt.Errorf("migrations %q and %q share version %d", prev, e.Name(), version)
		}
		seen[version] = e.Name()
		body, err := migrationFiles.ReadFile(path.Join("migrations", e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: version, name: desc, sql: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// Migrate applies every embedded migration not yet recorded in
// schema_migrations, holding a database-wide advisory lock for the duration.
// It is safe to call on every startup and from several replicas at once.
func Migrate(ctx context.Context, db *sql.DB) (err error) {
	migrations, err := loadMigrations()
	if err != nil {
		return fmt.Errorf("load migrations: %w", err)
	}

	// Advisory locks belong to a session, so lock, migrate and unlock on one
	// dedicated connection.
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrationLockKey); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		if _, uerr := conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrationLockKey); uerr != nil && err == nil {
			err = fmt.Errorf("release migration lock: %w", uerr)
		}
	}()

	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
	version BIGINT PRIMARY KEY,
	name TEXT NOT NULL,
	applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied, err := appliedMigrations(ctx, conn)
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		var existing bool
		if err := conn.QueryRowContext(ctx, `SELECT to_regclass('kms_keys') IS NOT NULL`).Scan(&existing); err != nil {
			return fmt.Errorf("detect existing schema: %w", err)
		}
		if existing {
			log.Printf("database predates versioned migrations; re-applying idempotent 0001_initial and recording it")
		}
	}

	for _, m := range migrations {
		if applied[m.version] {
			continue
		}
		if err := applyMigration(ctx, conn, m); err != nil {
			return fmt.Errorf("initialize schema: migration %04d_%s: %w", m.version, m.name, err)
		}
	}
	return nil
}

func appliedMigrations(ctx context.Context, conn *sql.Conn) (map[int64]bool, error) {
	rows, err := conn.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()
	out := map[int64]bool{}
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[v] = true
	}
	return out, rows.Err()
}

func applyMigration(ctx context.Context, conn *sql.Conn, m migration) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	// No arguments: lib/pq then uses the simple query protocol, which allows
	// several statements in one call.
	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return errors.Join(err, tx.Rollback())
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`, m.version, m.name); err != nil {
		return errors.Join(err, tx.Rollback())
	}
	return tx.Commit()
}
