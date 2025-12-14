package middleware

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"

	"github.com/davidthuman/service-spoof/internal/database"
	"github.com/davidthuman/service-spoof/internal/fingerprint"
	"github.com/davidthuman/service-spoof/internal/service"
)

// responseWriter wraps http.ResponseWriter to capture status code and template
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	template   string
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK, // default
	}
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Logger creates a logging middleware for a specific service
func Logger(requestLogger *database.RequestLogger, svc service.Service, serverPort int, ja4Store *fingerprint.JA4Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Dump the full HTTP request
			dump, err := httputil.DumpRequest(r, true)
			if err != nil {
				log.Printf("Error dumping request: %v", err)
				http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
				return
			}

			// Log to stdout (preserve existing behavior)
			log.Println(r.RemoteAddr, string(dump))

			// Wrap the response writer to capture status code
			wrappedWriter := newResponseWriter(w)

			// Determine which endpoint will be matched to get the template
			endpoint, matched := svc.Router().Match(r.Method, r.URL.Path)
			template := ""
			if matched {
				template = endpoint.Template
			}

			// Call the next handler
			next.ServeHTTP(wrappedWriter, r)

			// Extract JA4 fingerprint from store
			var ja4 *fingerprint.JA4Fingerprint
			if ja4Store != nil {
				ja4 = ja4Store.Get(r.RemoteAddr)
			}

			// Log to database
			err = requestLogger.LogRequest(
				r,
				serverPort,
				svc.Name(),
				svc.Type(),
				wrappedWriter.statusCode,
				template,
				dump,
				ja4,
			)
			if err != nil {
				log.Printf("Error logging request to database: %v", err)
			}
		})
	}
}
