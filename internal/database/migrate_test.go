package database

import (
	"path/filepath"
	"testing"
)

func TestRunMigrations_FreshDatabase(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	if err := db.RunMigrations("../../migrations"); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	// Verify table exists
	var count int
	err = db.conn.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='request_logs'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query tables: %v", err)
	}

	if count != 1 {
		t.Fatalf("Expected request_logs table to exist")
	}

	// Verify indexes exist
	err = db.conn.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query indexes: %v", err)
	}

	if count < 4 {
		t.Fatalf("Expected at least 4 indexes, got %d", count)
	}
}

func TestRunMigrations_ExistingDatabase(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Create database with old method
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	// Use old Initialize method to create schema
	if err := db.Initialize(); err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	// Insert test data
	_, err = db.conn.Exec(`INSERT INTO request_logs
		(source_ip, source_port, server_port, service_name, service_type,
		 method, path, protocol, headers, raw_request, response_status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"192.168.1.1", 12345, 8080, "test", "test",
		"GET", "/test", "HTTP/1.1", "{}", "raw", 200)
	if err != nil {
		t.Fatalf("Failed to insert test data: %v", err)
	}

	// Now run migrations
	if err := db.RunMigrations("../../migrations"); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	// Verify data still exists
	var count int
	err = db.conn.QueryRow("SELECT COUNT(*) FROM request_logs").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count rows: %v", err)
	}

	if count != 1 {
		t.Fatalf("Expected 1 row, got %d", count)
	}

	// Verify migration version
	version, dirty, err := db.GetMigrationVersion()
	if err != nil {
		t.Fatalf("Failed to get version: %v", err)
	}

	if dirty {
		t.Fatalf("Database is dirty")
	}

	if version != 1 {
		t.Fatalf("Expected version 1, got %d", version)
	}

	db.Close()
}

func TestRunMigrations_Idempotency(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Run migrations first time
	if err := db.RunMigrations("../../migrations"); err != nil {
		t.Fatalf("Failed to run migrations first time: %v", err)
	}

	// Run migrations second time - should be no-op
	if err := db.RunMigrations("../../migrations"); err != nil {
		t.Fatalf("Failed to run migrations second time: %v", err)
	}

	version, _, _ := db.GetMigrationVersion()
	if version == 0 {
		t.Fatalf("Expected version > 0 after migrations")
	}
}

func TestGetMigrationVersion(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Before migrations
	version, dirty, err := db.GetMigrationVersion()
	if err != nil {
		t.Fatalf("Failed to get version: %v", err)
	}

	if version != 0 {
		t.Fatalf("Expected version 0 for new database, got %d", version)
	}

	if dirty {
		t.Fatalf("Database should not be dirty before migrations")
	}

	// After migrations
	if err := db.RunMigrations("../../migrations"); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	version, dirty, err = db.GetMigrationVersion()
	if err != nil {
		t.Fatalf("Failed to get version after migrations: %v", err)
	}

	if dirty {
		t.Fatalf("Database is dirty after successful migration")
	}

	if version == 0 {
		t.Fatalf("Version should be > 0 after migrations")
	}
}

func TestRunMigrations_InvalidPath(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Try to run migrations with invalid path
	err = db.RunMigrations("/nonexistent/path")
	if err == nil {
		t.Fatalf("Expected error for invalid migrations path, got nil")
	}
}

func TestMigration_SchemaMatches(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	if err := db.RunMigrations("../../migrations"); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	// Verify table structure
	rows, err := db.conn.Query("PRAGMA table_info(request_logs)")
	if err != nil {
		t.Fatalf("Failed to get table info: %v", err)
	}
	defer rows.Close()

	columnNames := []string{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dfltValue interface{}

		if err := rows.Scan(&cid, &name, &typ, &notnull, &dfltValue, &pk); err != nil {
			t.Fatalf("Failed to scan row: %v", err)
		}
		columnNames = append(columnNames, name)
	}

	// Check for essential columns
	essentialColumns := []string{
		"id", "timestamp", "source_ip", "source_port", "server_port",
		"service_name", "service_type", "method", "path", "protocol",
		"headers", "raw_request", "response_status",
	}

	for _, col := range essentialColumns {
		found := false
		for _, actualCol := range columnNames {
			if actualCol == col {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected column %s not found in table", col)
		}
	}
}

func TestMigration_PreservesData(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Create database and insert data before migrations
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	// Initialize with old method
	if err := db.Initialize(); err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	// Insert multiple test records
	testData := []struct {
		ip     string
		port   int
		path   string
		method string
	}{
		{"192.168.1.1", 12345, "/test1", "GET"},
		{"192.168.1.2", 12346, "/test2", "POST"},
		{"192.168.1.3", 12347, "/test3", "PUT"},
	}

	for _, td := range testData {
		_, err = db.conn.Exec(`INSERT INTO request_logs
			(source_ip, source_port, server_port, service_name, service_type,
			 method, path, protocol, headers, raw_request, response_status)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			td.ip, td.port, 8080, "test", "test",
			td.method, td.path, "HTTP/1.1", "{}", "raw", 200)
		if err != nil {
			t.Fatalf("Failed to insert test data: %v", err)
		}
	}

	// Run migrations
	if err := db.RunMigrations("../../migrations"); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	// Verify all data still exists
	rows, err := db.conn.Query("SELECT source_ip, path, method FROM request_logs ORDER BY source_ip")
	if err != nil {
		t.Fatalf("Failed to query data: %v", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var ip, path, method string
		if err := rows.Scan(&ip, &path, &method); err != nil {
			t.Fatalf("Failed to scan row: %v", err)
		}

		if count < len(testData) {
			if ip != testData[count].ip || path != testData[count].path || method != testData[count].method {
				t.Errorf("Data mismatch at row %d: got (%s, %s, %s), expected (%s, %s, %s)",
					count, ip, path, method, testData[count].ip, testData[count].path, testData[count].method)
			}
		}
		count++
	}

	if count != len(testData) {
		t.Fatalf("Expected %d rows, got %d", len(testData), count)
	}

	db.Close()
}

func TestDatabase_CloseAndReopen(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// First connection - run migrations
	db1, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	if err := db1.RunMigrations("../../migrations"); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	v1, _, _ := db1.GetMigrationVersion()
	db1.Close()

	// Second connection - verify version persists
	db2, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to reopen database: %v", err)
	}
	defer db2.Close()

	v2, dirty, err := db2.GetMigrationVersion()
	if err != nil {
		t.Fatalf("Failed to get version on reopened database: %v", err)
	}

	if dirty {
		t.Fatalf("Database should not be dirty on reopen")
	}

	if v1 != v2 {
		t.Fatalf("Version changed after reopen: was %d, now %d", v1, v2)
	}

	// Run migrations again - should be no-op
	if err := db2.RunMigrations("../../migrations"); err != nil {
		t.Fatalf("Failed to run migrations on reopened database: %v", err)
	}

	v3, _, _ := db2.GetMigrationVersion()
	if v2 != v3 {
		t.Fatalf("Version changed after re-running migrations: was %d, now %d", v2, v3)
	}
}
