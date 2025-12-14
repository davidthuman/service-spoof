-- Add JA4 fingerprinting columns to request_logs table
ALTER TABLE request_logs ADD COLUMN ja4_fingerprint TEXT;
ALTER TABLE request_logs ADD COLUMN ja4_part_a TEXT;
ALTER TABLE request_logs ADD COLUMN ja4_part_b TEXT;
ALTER TABLE request_logs ADD COLUMN ja4_part_c TEXT;
ALTER TABLE request_logs ADD COLUMN tls_version TEXT;
ALTER TABLE request_logs ADD COLUMN tls_sni TEXT;
ALTER TABLE request_logs ADD COLUMN tls_cipher_count INTEGER;

-- Create indexes for efficient JA4 lookups
CREATE INDEX IF NOT EXISTS idx_ja4_fingerprint ON request_logs(ja4_fingerprint);
CREATE INDEX IF NOT EXISTS idx_tls_version ON request_logs(tls_version);
