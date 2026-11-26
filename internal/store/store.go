// Package store persists Sentrix state. The default backend is SQLite (pure Go,
// WAL mode). All SQL is kept ANSI-portable so a PostgreSQL backend can implement
// the same methods (see docs/DECISIONS.md).
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// DB is the Sentrix datastore.
type DB struct {
	sql *sql.DB
	now func() time.Time
}

// Open opens (creating if needed) the SQLite database at path and applies migrations.
func Open(ctx context.Context, path string) (*DB, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	if path == ":memory:" {
		dsn = "file::memory:?_pragma=foreign_keys(1)"
	}
	sdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// SQLite allows one writer; a single connection avoids SQLITE_BUSY storms and keeps
	// in-memory databases coherent. Reads are fast enough for the target fleet size.
	sdb.SetMaxOpenConns(1)
	if err := sdb.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	if err := migrate(ctx, sdb); err != nil {
		return nil, err
	}
	return &DB{sql: sdb, now: time.Now}, nil
}

// Close closes the database.
func (d *DB) Close() error { return d.sql.Close() }

// SQL exposes the underlying handle (used by tests and maintenance jobs).
func (d *DB) SQL() *sql.DB { return d.sql }

// SetClock overrides the time source (tests).
func (d *DB) SetClock(f func() time.Time) { d.now = f }

// HashToken returns the hex SHA-256 used to store secret tokens.
func HashToken(tok string) string {
	s := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(s[:])
}

// GetSetting returns a setting value or "" if absent.
func (d *DB) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := d.sql.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetSetting upserts a setting.
func (d *DB) SetSetting(ctx context.Context, key, value string) error {
	_, err := d.sql.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}
