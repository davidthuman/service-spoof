-- Add Column fingerprint to request_logs table
ALTER TABLE request_logs ADD COLUMN fingerprint TEXT NOT NULL DEFAULT "";

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_fingerprint ON request_logs(fingerprint);