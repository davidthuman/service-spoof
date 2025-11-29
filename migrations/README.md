# Database Migrations

This directory contains database migration files managed by [golang-migrate](https://github.com/golang-migrate/migrate).

## Overview

Migrations provide version control for the database schema, allowing:
- Trackable schema changes over time
- Rollback capability for database changes
- Team collaboration on schema evolution
- Automated deployment of schema updates

## Migration Files

Migrations are paired files with `.up.sql` and `.down.sql` extensions:
- **Up migration**: Applies the schema change
- **Down migration**: Reverts the schema change

### Naming Convention

Format: `NNNNNN_description.{up,down}.sql`

- Use 6-digit sequential numbers: `000001`, `000002`, `000003`, etc.
- Use snake_case for description
- Keep descriptions concise but meaningful

Examples:
```
000001_initial_schema.up.sql
000001_initial_schema.down.sql
000002_add_geolocation_columns.up.sql
000002_add_geolocation_columns.down.sql
000003_create_alerts_table.up.sql
000003_create_alerts_table.down.sql
```

## Adding New Migrations

### Step 1: Create Migration Files

Find the next sequential number and create both up and down files:

```bash
# If 000001 exists, create 000002
touch migrations/000002_add_geolocation_columns.up.sql
touch migrations/000002_add_geolocation_columns.down.sql
```

### Step 2: Write the Up Migration

Add the schema changes you want to apply:

```sql
-- migrations/000002_add_geolocation_columns.up.sql
ALTER TABLE request_logs ADD COLUMN country TEXT;
ALTER TABLE request_logs ADD COLUMN city TEXT;
ALTER TABLE request_logs ADD COLUMN latitude REAL;
ALTER TABLE request_logs ADD COLUMN longitude REAL;

CREATE INDEX idx_country ON request_logs(country);
```

### Step 3: Write the Down Migration

Add the reverse operations to undo the changes:

```sql
-- migrations/000002_add_geolocation_columns.down.sql
DROP INDEX IF EXISTS idx_country;

-- Note: SQLite doesn't support DROP COLUMN in older versions
-- For production, consider recreating the table without these columns
-- or document that columns will remain but be unused after rollback
```

### Step 4: Test Locally

Before committing, test both up and down migrations:

```bash
# Build and run the application
go build -o service-spoof .
./service-spoof

# Verify the migration was applied
sqlite3 data/service-spoof.db "SELECT version FROM schema_migrations;"
sqlite3 data/service-spoof.db "PRAGMA table_info(request_logs);"

# Test that the application works correctly
curl http://localhost:8070/test

# Check the database for logged requests
sqlite3 data/service-spoof.db "SELECT COUNT(*) FROM request_logs;"
```

### Step 5: Commit

Commit both migration files together:

```bash
git add migrations/000002_add_geolocation_columns.up.sql
git add migrations/000002_add_geolocation_columns.down.sql
git commit -m "feat: add geolocation columns to request logs"
```

## Best Practices

### Do's

- ✅ Keep migrations small and focused on a single change
- ✅ Always provide both up and down migrations
- ✅ Test migrations on a copy of production data before deploying
- ✅ Use `IF EXISTS` and `IF NOT EXISTS` clauses for safety
- ✅ Add indexes for columns used in WHERE clauses
- ✅ Document complex migrations with comments
- ✅ Commit migration files with the code that uses them

### Don'ts

- ❌ Never modify existing migration files after they've been deployed
- ❌ Don't skip migration numbers
- ❌ Don't make migrations dependent on application code
- ❌ Don't include data changes in schema migrations (use separate data migrations)
- ❌ Don't use database-specific SQL if possible (keep it portable)

## SQLite Limitations

Be aware of SQLite's ALTER TABLE limitations:

- ✅ Supported: ADD COLUMN, RENAME TO, RENAME COLUMN (SQLite 3.25.0+)
- ❌ Not supported: DROP COLUMN (SQLite < 3.35.0), ADD CONSTRAINT, etc.

For unsupported operations, you'll need to:
1. Create a new table with the desired schema
2. Copy data from the old table
3. Drop the old table
4. Rename the new table

Example:
```sql
-- Create new table with changes
CREATE TABLE request_logs_new (...);

-- Copy data
INSERT INTO request_logs_new SELECT ... FROM request_logs;

-- Drop old table
DROP TABLE request_logs;

-- Rename new table
ALTER TABLE request_logs_new RENAME TO request_logs;

-- Recreate indexes
CREATE INDEX ...;
```

## Migration State

The `schema_migrations` table tracks the current migration version:

```sql
-- Check current version
SELECT version, dirty FROM schema_migrations;
```

- `version`: The last successfully applied migration number
- `dirty`: Whether a migration failed mid-execution (should always be `false`)

## Troubleshooting

### Dirty State

If a migration fails, the database will be marked as "dirty":

```
Database is in dirty state at version 2
```

Recovery steps:
1. Check application logs for the specific error
2. Examine the database: `sqlite3 data/service-spoof.db "SELECT * FROM schema_migrations;"`
3. Fix the underlying issue (corrupt SQL, missing file, etc.)
4. Manually complete the migration or roll it back
5. Update schema_migrations: `UPDATE schema_migrations SET dirty = false;`
6. Restart the application

### Migration Not Found

```
Error: file does not exist
```

Ensure:
- The migrations directory exists
- Migration files are named correctly
- Files have `.up.sql` and `.down.sql` extensions
- The application can read the migrations directory

### No Migrations Run

If migrations seem to be skipped, check:
- Are migration files in the correct location (`./migrations/`)?
- Do files have the correct naming format?
- Is the database connection successful?
- Check logs for any errors

## Manual Migration Commands

While the application handles migrations automatically, you can use the migrate CLI for manual operations:

```bash
# Install migrate CLI
go install -tags 'sqlite3' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# Check version
migrate -source file://migrations -database sqlite3://data/service-spoof.db version

# Apply all pending migrations
migrate -source file://migrations -database sqlite3://data/service-spoof.db up

# Rollback one migration
migrate -source file://migrations -database sqlite3://data/service-spoof.db down 1

# Force version (use with caution!)
migrate -source file://migrations -database sqlite3://data/service-spoof.db force 1
```

## Resources

- [golang-migrate Documentation](https://github.com/golang-migrate/migrate)
- [SQLite ALTER TABLE Documentation](https://www.sqlite.org/lang_altertable.html)
- [Migration Best Practices](https://github.com/golang-migrate/migrate/blob/master/MIGRATIONS.md)
