-- Drop indexes
DROP INDEX IF EXISTS idx_tls_version;
DROP INDEX IF EXISTS idx_ja4_fingerprint;

-- Remove columns (SQLite limitation: must recreate table)
-- Create temporary table without JA4 columns
CREATE TABLE request_logs_backup AS
SELECT id, timestamp, source_ip, source_port, server_port,
       service_name, service_type, method, path, protocol,
       host, user_agent, headers, body, raw_request,
       response_status, response_template
FROM request_logs;

DROP TABLE request_logs;
ALTER TABLE request_logs_backup RENAME TO request_logs;

-- Recreate original indexes
CREATE INDEX IF NOT EXISTS idx_timestamp ON request_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_source_ip ON request_logs(source_ip);
CREATE INDEX IF NOT EXISTS idx_service_name ON request_logs(service_name);
CREATE INDEX IF NOT EXISTS idx_path ON request_logs(path);
