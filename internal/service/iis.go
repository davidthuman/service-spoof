package service

import (
	"fmt"
	"net/http"
	"os"

	"github.com/davidthuman/service-spoof/internal/config"
)

// IISService implements the Microsoft IIS service
type IISService struct {
	name    string
	sType   string
	headers map[string]string
	router  *Router
}

// NewIISService creates a new IIS service instance
func NewIISService(cfg *config.ServiceConfig) (*IISService, error) {
	s := &IISService{
		name:    cfg.Name,
		sType:   cfg.Type,
		headers: cfg.Headers,
		router:  NewRouter(),
	}

	// Build router from config endpoints
	for _, ep := range cfg.Endpoints {
		s.router.AddEndpoint(&Endpoint{
			Path:     ep.Path,
			Method:   ep.Method,
			Status:   ep.Status,
			Template: ep.Template,
			Headers:  ep.Headers,
		})
	}

	return s, nil
}

// Name returns the service name
func (s *IISService) Name() string {
	return s.name
}

// Type returns the service type
func (s *IISService) Type() string {
	return s.sType
}

// Headers returns the default headers
func (s *IISService) Headers() map[string]string {
	return s.headers
}

// Router returns the endpoint router
func (s *IISService) Router() *Router {
	return s.router
}

// HandleRequest handles an HTTP request
func (s *IISService) HandleRequest(w http.ResponseWriter, r *http.Request) {
	// Match the request to an endpoint
	endpoint, matched := s.router.Match(r.Method, r.URL.Path)
	if !matched {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Apply endpoint-specific headers
	for k, v := range endpoint.Headers {
		w.Header().Set(k, v)
	}

	// Set the status code
	w.WriteHeader(endpoint.Status)

	// Load and serve the template if specified
	if endpoint.Template != "" {
		content, err := os.ReadFile(endpoint.Template)
		if err != nil {
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		w.Write(content)
	}
}
