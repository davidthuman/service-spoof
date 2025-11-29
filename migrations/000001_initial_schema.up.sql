-- Create request_logs table
CREATE TABLE IF NOT EXISTS request_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Connection info
    source_ip TEXT NOT NULL,
    source_port INTEGER NOT NULL,
    server_port INTEGER NOT NULL,

    -- Service info
    service_name TEXT NOT NULL,
    service_type TEXT NOT NULL,

    -- Request details (parsed)
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    protocol TEXT NOT NULL,
    host TEXT,
    user_agent TEXT,
    headers TEXT NOT NULL,
    body TEXT,

    -- Full raw dump
    raw_request TEXT NOT NULL,

    -- Response info
    response_status INTEGER NOT NULL,
    response_template TEXT
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_timestamp ON request_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_source_ip ON request_logs(source_ip);
CREATE INDEX IF NOT EXISTS idx_service_name ON request_logs(service_name);
CREATE INDEX IF NOT EXISTS idx_path ON request_logs(path);
