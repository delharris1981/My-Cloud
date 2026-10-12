// Package sqlite owns the SQLite database: connection setup, schema creation,
// and the first-boot migration from the Node version's JSON stores.
//
// The driver is modernc.org/sqlite (pure Go) so CGO_ENABLED=0 static builds
// keep working and the binary stays self-contained.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// openTimeout bounds startup so a locked volume fails loudly instead of
// hanging the container's health check forever.
const openTimeout = 10 * time.Second

// DB wraps the database handle and the sealer used for encryption at rest.
type DB struct {
	*sql.DB
	path string
}

// Open creates or opens the database at path and ensures the schema exists.
//
// On a fresh database the full schema is applied and schema_meta.version is
// stamped. On an existing one the schema statements are idempotent (IF NOT
// EXISTS), so Open is safe to call repeatedly.
//
// It does NOT run the first-boot migration; call Migrate explicitly so the
// caller controls the ordering relative to serving traffic.
func Open(path string) (*DB, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("sqlite: create db dir: %w", err)
		}
	}

	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)"
	sdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	// SQLite tolerates exactly one writer. Unlimited connections would only
	// produce SQLITE_BUSY under concurrent writes, and modernc's driver
	// serialises internally anyway. Bounding it also keeps the busy_timeout
	// the real backstop.
	sdb.SetMaxOpenConns(1)
	sdb.SetMaxIdleConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), openTimeout)
	defer cancel()
	if err := sdb.PingContext(ctx); err != nil {
		sdb.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}

	db := &DB{DB: sdb, path: path}
	if err := db.ensureSchema(ctx); err != nil {
		sdb.Close()
		return nil, err
	}
	return db, nil
}

func (db *DB) ensureSchema(ctx context.Context) error {
	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("sqlite: apply schema: %w", err)
	}
	// Stamp the version only if absent. Do not overwrite: a database mid-way
	// through the Node migration records its version deliberately.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO schema_meta(key, value) VALUES('version', ?)
		 ON CONFLICT(key) DO NOTHING`, SchemaVersion); err != nil {
		return fmt.Errorf("sqlite: stamp version: %w", err)
	}
	return nil
}

// Version returns the recorded schema version, or 0 if unset.
func (db *DB) Version(ctx context.Context) (int, error) {
	var v int
	err := db.QueryRowContext(ctx, `SELECT value FROM schema_meta WHERE key='version'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("sqlite: read version: %w", err)
	}
	return v, nil
}

// Migrated reports whether the first-boot migration has already run. The
// migration stamps schema_meta with a second key so the presence of legacy
// JSON files alone is never the signal — an operator who restores
// users.json after a successful migration must not trigger it again.
func (db *DB) Migrated(ctx context.Context) (bool, error) {
	var v string
	err := db.QueryRowContext(ctx,
		`SELECT value FROM schema_meta WHERE key='node_migrated_at'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("sqlite: read migration marker: %w", err)
	}
	return true, nil
}

// IsEmpty reports whether no users exist. Drives the first-boot setup wizard:
// with no users, setup is open to the world, so this must never be true by
// accident (e.g. a failed migration that dropped the users table).
func (db *DB) IsEmpty(ctx context.Context) (bool, error) {
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return false, fmt.Errorf("sqlite: count users: %w", err)
	}
	return n == 0, nil
}
