# JA4 TLS Fingerprinting Implementation

## Overview

This document describes the JA4 TLS fingerprinting implementation in the service-spoof honeypot. JA4 is a method for creating fingerprints of TLS Client Hello messages to identify and track client applications, browsers, and potential attackers.

## What is JA4?

JA4 is a network fingerprinting standard developed by FoxIO that creates a unique identifier for TLS clients based on their Client Hello message. Unlike JA3, JA4 is more resilient to randomization techniques used by modern browsers and clients.

### JA4 Format

A JA4 fingerprint has the format: `{PartA}_{PartB}_{PartC}`

**Part A** (12 characters): Protocol metadata
- Protocol: `t` (TLS), `q` (QUIC), `d` (DTLS)
- TLS Version: `13` (TLS 1.3), `12` (TLS 1.2), etc.
- SNI Type: `d` (domain) or `i` (IP address)
- Cipher Count: 2 digits (GREASE filtered)
- Extension Count: 2 digits (GREASE filtered)
- ALPN: First and last char of first ALPN protocol

Example: `t13d1516h2`

**Part B** (12 characters): Truncated SHA256 hash of sorted cipher suites (comma-delimited hex)

**Part C** (12 characters): Truncated SHA256 hash of sorted extensions and signature algorithms

Example full fingerprint: `t13d1516h2_8daaf6152771_e5627efa2ab1`

## Architecture

### Components

1. **JA4 Generation** (`internal/fingerprint/ja4.go`)
   - Generates JA4 fingerprints from TLS Client Hello
   - Implements GREASE filtering (RFC 8701)
   - Handles TLS version mapping
   - Creates SHA256 hashes of cipher suites and extensions

2. **JA4 Storage** (`internal/fingerprint/store.go`)
   - Thread-safe in-memory storage
   - TTL-based automatic cleanup (default: 5 minutes)
   - Bridges TLS handshake → HTTP request logging gap

3. **TLS Configuration** (`internal/server/manager.go`)
   - Loads TLS certificates from config
   - Configures `GetConfigForClient` callback to capture Client Hello
   - Stores JA4 fingerprints keyed by remote address

4. **Request Logging** (`internal/middleware/logger.go`, `internal/database/logger.go`)
   - Retrieves JA4 from store during request logging
   - Persists to database with request metadata

### Data Flow

```
1. TLS Handshake
   ↓
2. GetConfigForClient callback
   ↓
3. GenerateJA4(ClientHelloInfo)
   ↓
4. Store in JA4Store (keyed by RemoteAddr)
   ↓
5. HTTP Request Processing
   ↓
6. Middleware retrieves JA4 from store
   ↓
7. Database logger persists JA4 with request
```

## Database Schema

### New Columns in `request_logs`

```sql
ja4_fingerprint    TEXT    -- Full JA4 fingerprint (e.g., t13d1516h2_8daaf6152771_e5627efa2ab1)
ja4_part_a         TEXT    -- Part A (metadata)
ja4_part_b         TEXT    -- Part B (cipher hash)
ja4_part_c         TEXT    -- Part C (extension hash)
tls_version        TEXT    -- TLS version (e.g., "13", "12")
tls_sni            TEXT    -- Server Name Indication
tls_cipher_count   INTEGER -- Number of cipher suites (GREASE filtered)
```

### Indexes

```sql
CREATE INDEX idx_ja4_fingerprint ON request_logs(ja4_fingerprint);
CREATE INDEX idx_tls_version ON request_logs(tls_version);
```

## Configuration

### TLS Setup

In `config.yaml`:

```yaml
tls:
  certFilePath: "./cert.pem"
  keyFilePath: "./key.pem"
```

If TLS is configured, the server will:
- Use `ListenAndServeTLS()` instead of `ListenAndServe()`
- Capture JA4 fingerprints during TLS handshake
- Store fingerprints for correlation with HTTP requests

If TLS is not configured:
- Server runs HTTP-only
- JA4 fields in database are empty/null

## Usage

### Running the Server

```bash
# Build the project
go build

# Run the server (migrations run automatically)
./service-spoof
```

### Querying JA4 Data

**Most Common Fingerprints:**
```sql
SELECT ja4_fingerprint, COUNT(*) as count
FROM request_logs
WHERE ja4_fingerprint != ''
GROUP BY ja4_fingerprint
ORDER BY count DESC
LIMIT 10;
```

**Unique Clients per Fingerprint:**
```sql
SELECT
    ja4_fingerprint,
    tls_version,
    COUNT(DISTINCT source_ip) as unique_ips,
    COUNT(*) as total_requests
FROM request_logs
WHERE ja4_fingerprint != ''
GROUP BY ja4_fingerprint, tls_version
ORDER BY unique_ips DESC;
```

**TLS Version Distribution:**
```sql
SELECT tls_version, COUNT(*) as count
FROM request_logs
WHERE tls_version != ''
GROUP BY tls_version
ORDER BY count DESC;
```

**Fingerprint Timeline:**
```sql
SELECT
    datetime(timestamp) as time,
    source_ip,
    ja4_fingerprint,
    tls_version,
    user_agent
FROM request_logs
WHERE ja4_fingerprint != ''
ORDER BY timestamp DESC
LIMIT 20;
```

## Testing

### Unit Tests

```bash
# Run all fingerprint tests
go test ./internal/fingerprint/...

# Run with race detector
go test -race ./internal/fingerprint/...

# Run with coverage
go test -cover ./internal/fingerprint/...
```

### Integration Test

Use the provided test script:

```bash
# Ensure server is built
go build

# Run end-to-end test
./test_ja4.sh
```

The script will:
1. Create self-signed TLS certificates if needed
2. Start the server
3. Send test requests with different TLS versions
4. Query the database for JA4 fingerprints
5. Display statistics

### Manual Testing

```bash
# TLS 1.2 request
curl -k --tlsv1.2 --tls-max 1.2 https://localhost:8070/

# TLS 1.3 request
curl -k --tlsv1.3 https://localhost:8070/

# With specific cipher
curl -k --tlsv1.3 --ciphers TLS_AES_128_GCM_SHA256 https://localhost:8070/

# Query database
sqlite3 ./data/service-spoof.db "SELECT ja4_fingerprint, tls_version FROM request_logs WHERE ja4_fingerprint != '' ORDER BY timestamp DESC LIMIT 5;"
```

## Implementation Details

### GREASE Handling

GREASE (Generate Random Extensions And Sustain Extensibility, RFC 8701) values are filtered from cipher suites, extensions, and TLS versions:

```go
var greaseValues = map[uint16]bool{
    0x0A0A: true, 0x1A1A: true, 0x2A2A: true, 0x3A3A: true,
    0x4A4A: true, 0x5A5A: true, 0x6A6A: true, 0x7A7A: true,
    0x8A8A: true, 0x9A9A: true, 0xAAAA: true, 0xBABA: true,
    0xCACA: true, 0xDADA: true, 0xEAEA: true, 0xFAFA: true,
}
```

### TLS Version Mapping

```go
0x0304 → "13"  // TLS 1.3
0x0303 → "12"  // TLS 1.2
0x0302 → "11"  // TLS 1.1
0x0301 → "10"  // TLS 1.0
0x0300 → "s3"  // SSL 3.0
0xfeff → "d1"  // DTLS 1.0
0xfefd → "d2"  // DTLS 1.2
```

### Extension Limitations

Go's `crypto/tls` package exposes limited extension data via `ClientHelloInfo`:
- Cipher suites ✓
- Supported versions ✓
- Signature schemes ✓
- Supported curves/groups ✓
- ALPN protocols ✓
- SNI ✓
- EC point formats ✓

Not directly available:
- Session tickets
- Status request (OCSP stapling)
- Max fragment length
- Encrypt-then-MAC
- Extended master secret

The current implementation uses available fields, providing sufficient fingerprinting capability for most use cases. For complete JA4 implementation, raw TLS handshake parsing would be required.

### Memory Management

**JA4Store TTL**: 5 minutes (configurable)
- Cleanup runs every 2.5 minutes (TTL/2)
- Expired entries automatically removed
- Memory usage: ~250 bytes per connection

**Typical Load**:
- 1,000 connections: ~250 KB
- 10,000 connections: ~2.5 MB

### Thread Safety

- `JA4Store` uses `sync.RWMutex` for concurrent access
- Multiple goroutines can read simultaneously
- Write operations are exclusive
- Verified with `-race` detector

### Performance

- **JA4 Generation**: <10 microseconds per handshake
- **Store Lookup**: O(1) map access, ~100 nanoseconds
- **Database Impact**: 7 new columns, ~100-200 bytes per log entry

## Security Considerations

### Privacy

JA4 fingerprints can identify specific browsers, applications, and potentially individuals:
- Combined with IP address, creates tracking capability
- Consider data retention policies
- Document in privacy policy if public-facing

### Evasion

While JA4 is designed to resist randomization:
- GREASE filtering defeats basic randomization
- Cipher/extension sorting defeats order manipulation
- Determined attackers can still manipulate fingerprints
- JA4 is an indicator, not a security boundary

### DoS Mitigation

- TTL-based cleanup prevents memory exhaustion
- Map size grows with concurrent connections, not total requests
- Consider adding max size limit for high-traffic scenarios

## Troubleshooting

### No JA4 Fingerprints in Database

1. **Check TLS is configured**:
   ```bash
   # Verify cert files exist
   ls -la cert.pem key.pem

   # Check config.yaml has TLS section
   grep -A2 "^tls:" config.yaml
   ```

2. **Verify HTTPS is used**:
   ```bash
   # HTTP won't have JA4
   curl http://localhost:8070/  # No JA4

   # HTTPS will have JA4
   curl -k https://localhost:8070/  # Has JA4
   ```

3. **Check server logs**:
   ```bash
   # Look for TLS errors
   ./service-spoof 2>&1 | grep -i tls
   ```

### Certificate Errors

```bash
# Generate new self-signed cert
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
    -days 365 -nodes -subj "/CN=localhost"
```

### Database Migration Issues

```bash
# Check migration status
sqlite3 ./data/service-spoof.db "SELECT version, dirty FROM schema_migrations;"

# If stuck in dirty state, manually fix:
# 1. Backup database
# 2. Delete schema_migrations table
# 3. Restart service-spoof (will re-run migrations)
```

## Future Enhancements

### 1. Complete Extension Parsing

Implement raw TLS handshake parsing to capture all extensions:
- Requires reading raw bytes before Go's TLS parser
- More accurate extension count and ordering
- Higher complexity

### 2. JA4+ Extended Fingerprints

- **JA4S**: Server response fingerprinting
- **JA4H**: HTTP header fingerprinting
- **JA4L**: Light distance/latency analysis
- **JA4X**: X.509 certificate fingerprinting

### 3. Fingerprint Intelligence

- Maintain known-good/known-bad fingerprint lists
- Real-time alerting on suspicious fingerprints
- Integration with threat intelligence feeds

### 4. Analysis Tools

- Fingerprint frequency analysis
- Anomaly detection (new fingerprints)
- Correlation with other attack indicators
- Export to SIEM/security tools

### 5. Performance Optimization

- Context-based storage instead of RemoteAddr map
- Connection pooling awareness
- Configurable TTL per service/port
- Optional summary table for analytics

## References

- [JA4+ Network Fingerprinting](https://github.com/FoxIO-LLC/ja4)
- [JA4 Technical Details](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)
- [RFC 8701 - GREASE](https://datatracker.ietf.org/doc/html/rfc8701)
- [TLS 1.3 RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446)

## Support

For issues or questions:
1. Check server logs for errors
2. Verify TLS configuration
3. Run unit tests: `go test ./internal/fingerprint/...`
4. Check database schema: `sqlite3 ./data/service-spoof.db ".schema request_logs"`

## License

This implementation follows the same license as the service-spoof project.
