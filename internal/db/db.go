package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	_ "modernc.org/sqlite"
)

func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	for _, q := range []string{"PRAGMA journal_mode=WAL;", "PRAGMA foreign_keys=ON;"} {
		if _, err := db.Exec(q); err != nil {
			return nil, err
		}
	}
	return db, nil
}

func Migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return err
	}
	_, this, _, _ := runtime.Caller(0)
	base := filepath.Clean(filepath.Join(filepath.Dir(this), "..", ".."))
	files, err := filepath.Glob(filepath.Join(base, "migrations", "*.sql"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, f := range files {
		n := filepath.Base(f)
		var c int
		if err := db.QueryRow(`SELECT COUNT(1) FROM schema_migrations WHERE version=?`, n).Scan(&c); err != nil {
			return err
		}
		if c > 0 {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(string(b)); err != nil {
			tx.Rollback()
			return fmt.Errorf("%s: %w", f, err)
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(?,?)`, n, time.Now().Unix()); err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
