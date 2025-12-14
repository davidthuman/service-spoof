#!/bin/bash

# JA4 Fingerprinting End-to-End Test Script
# This script tests the JA4 fingerprinting implementation

set -e

echo "=== JA4 Fingerprinting Test ==="
echo ""

# Check if cert files exist
if [ ! -f "./cert.pem" ] || [ ! -f "./key.pem" ]; then
    echo "Creating self-signed TLS certificate..."
    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" 2>/dev/null
    echo "✓ Certificate created"
    echo ""
fi

# Start the server in background
echo "Starting service-spoof server..."
./service-spoof &
SERVER_PID=$!
echo "✓ Server started (PID: $SERVER_PID)"
echo ""

# Wait for server to be ready
sleep 2

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Cleaning up..."
    kill $SERVER_PID 2>/dev/null || true
    echo "✓ Server stopped"
}
trap cleanup EXIT

# Test 1: HTTPS request with curl (TLS 1.2)
echo "Test 1: curl with TLS 1.2"
curl -k --tlsv1.2 --tls-max 1.2 https://localhost:8070/ > /dev/null 2>&1 || true
echo "✓ Request sent"
echo ""

# Test 2: HTTPS request with curl (TLS 1.3)
echo "Test 2: curl with TLS 1.3"
curl -k --tlsv1.3 https://localhost:8070/ > /dev/null 2>&1 || true
echo "✓ Request sent"
echo ""

# Wait for requests to be logged
sleep 1

# Query database for JA4 fingerprints
echo "Querying database for JA4 fingerprints..."
echo ""

sqlite3 ./data/service-spoof.db <<EOF
.headers on
.mode column
SELECT
    source_ip,
    server_port,
    tls_version,
    tls_cipher_count,
    ja4_fingerprint,
    datetime(timestamp) as request_time
FROM request_logs
WHERE ja4_fingerprint IS NOT NULL AND ja4_fingerprint != ''
ORDER BY timestamp DESC
LIMIT 10;
EOF

echo ""
echo "=== JA4 Statistics ==="
sqlite3 ./data/service-spoof.db <<EOF
.headers on
.mode column
SELECT
    ja4_fingerprint,
    tls_version,
    COUNT(*) as count,
    COUNT(DISTINCT source_ip) as unique_ips
FROM request_logs
WHERE ja4_fingerprint IS NOT NULL AND ja4_fingerprint != ''
GROUP BY ja4_fingerprint, tls_version
ORDER BY count DESC;
EOF

echo ""
echo "=== Test Complete ==="
