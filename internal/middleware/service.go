package middleware

import (
	"net/http"

	"github.com/davidthuman/service-spoof/internal/service"
)

// ServiceHeaders creates middleware that applies service-specific headers
func ServiceHeaders(svc service.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Apply service-specific headers
			for k, v := range svc.Headers() {
				w.Header().Set(k, v)
			}

			// Call the next handler
			next.ServeHTTP(w, r)
		})
	}
}
