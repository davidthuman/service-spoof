-- Drop indexes
DROP INDEX IF EXISTS idx_path;
DROP INDEX IF EXISTS idx_service_name;
DROP INDEX IF EXISTS idx_source_ip;
DROP INDEX IF EXISTS idx_timestamp;

-- Drop table
DROP TABLE IF EXISTS request_logs;
