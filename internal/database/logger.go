package database

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/davidthuman/service-spoof/internal/fingerprint"
)

// RequestLogger handles logging HTTP requests to the database
type RequestLogger struct {
	db *DB
}

// NewRequestLogger creates a new request logger
func NewRequestLogger(db *DB) *RequestLogger {
	return &RequestLogger{db: db}
}

// RequestLog represents a logged HTTP request
type RequestLog struct {
	ID               int64
	Timestamp        time.Time
	SourceIP         string
	SourcePort       int
	JA4Fingerprint   string
	ServerPort       int
	ServiceName      string
	ServiceType      string
	Method           string
	Path             string
	Protocol         string
	Host             string
	UserAgent        string
	Headers          string
	Body             string
	RawRequest       string
	ResponseStatus   int
	ResponseTemplate string
}

// LogRequest logs an HTTP request to the database
func (rl *RequestLogger) LogRequest(
	r *http.Request,
	serverPort int,
	serviceName string,
	serviceType string,
	responseStatus int,
	responseTemplate string,
	rawDump []byte,
) error {
	// Parse source IP and port
	sourceIP, sourcePort := parseRemoteAddr(r.RemoteAddr)

	// Marshal headers to JSON
	headersJSON, err := json.Marshal(r.Header)
	if err != nil {
		return fmt.Errorf("failed to marshal headers: %w", err)
	}

	// Read request body if present
	// Note: The body should already be read in the middleware that calls this
	// We'll just store empty for now as we're using rawDump for full request
	body := ""

	// Get user agent
	userAgent := r.Header.Get("User-Agent")

	// Get connection fingerprint from request context
	fingerprint := r.Context().Value(fingerprint.JA4)

	// Insert into database
	query := `
		INSERT INTO request_logs (
			timestamp, source_ip, source_port, fingerprint, server_port,
			service_name, service_type,
			method, path, protocol, host, user_agent,
			headers, body, raw_request,
			response_status, response_template
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = rl.db.conn.Exec(
		query,
		time.Now(),
		sourceIP,
		sourcePort,
		fingerprint,
		serverPort,
		serviceName,
		serviceType,
		r.Method,
		r.URL.Path,
		r.Proto,
		r.Host,
		userAgent,
		string(headersJSON),
		body,
		string(rawDump),
		responseStatus,
		responseTemplate,
	)

	if err != nil {
		return fmt.Errorf("failed to insert request log: %w", err)
	}

	return nil
}

// parseRemoteAddr parses the remote address into IP and port
func parseRemoteAddr(remoteAddr string) (string, int) {
	// Format is typically "ip:port"
	parts := strings.Split(remoteAddr, ":")
	if len(parts) < 2 {
		return remoteAddr, 0
	}

	// Handle IPv6 addresses which have multiple colons
	// For simplicity, we'll just take the last part as port
	port := 0
	portStr := parts[len(parts)-1]
	fmt.Sscanf(portStr, "%d", &port)

	// IP is everything except the last part
	ip := strings.Join(parts[:len(parts)-1], ":")
	ip = strings.Trim(ip, "[]") // Remove brackets from IPv6

	return ip, port
}
