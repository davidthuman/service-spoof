package database

import (
	"fmt"
	"path/filepath"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite3"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// RunMigrations runs all pending database migrations
func (db *DB) RunMigrations(migrationsPath string) error {
	// Convert relative path to absolute if needed
	absPath, err := filepath.Abs(migrationsPath)
	if err != nil {
		return fmt.Errorf("failed to resolve migrations path: %w", err)
	}

	// Create migration driver for SQLite
	driver, err := sqlite3.WithInstance(db.conn, &sqlite3.Config{})
	if err != nil {
		return fmt.Errorf("failed to create migration driver: %w", err)
	}

	// Create migrate instance
	m, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", absPath),
		"sqlite3",
		driver,
	)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}

	// Run migrations
	err = m.Up()
	if err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}

// GetMigrationVersion returns the current migration version and dirty state
// by directly querying the schema_migrations table
func (db *DB) GetMigrationVersion() (uint, bool, error) {
	var version uint
	var dirty bool

	// Check if schema_migrations table exists
	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'").Scan(&count)
	if err != nil {
		return 0, false, fmt.Errorf("failed to check for schema_migrations table: %w", err)
	}

	// If table doesn't exist, no migrations have been run
	if count == 0 {
		return 0, false, nil
	}

	// Query the version and dirty state
	err = db.conn.QueryRow("SELECT version, dirty FROM schema_migrations LIMIT 1").Scan(&version, &dirty)
	if err != nil {
		// No rows means no migrations have been run
		return 0, false, nil
	}

	return version, dirty, nil
}
