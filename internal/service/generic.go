package service

import (
	"fmt"
	"net/http"
	"os"

	"github.com/davidthuman/service-spoof/internal/config"
)

// Implements a generic service
type GenericService struct {
	name    string
	sType   string
	headers map[string]string
	router  *Router
}

// Creates a new Generic Service instance
func NewGenericService(cfg *config.ServiceConfig) (*GenericService, error) {
	s := &GenericService{
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
func (s *GenericService) Name() string {
	return s.name
}

// Type returns the service type
func (s *GenericService) Type() string {
	return s.sType
}

// Headers returns the default headers
func (s *GenericService) Headers() map[string]string {
	return s.headers
}

// Router returns the endpoint router
func (s *GenericService) Router() *Router {
	return s.router
}

func (s *GenericService) HandleRequest(w http.ResponseWriter, r *http.Request) {

	// Match the requet to can endpoint
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

	// Load and server the template if specified
	if endpoint.Template != "" {
		content, err := os.ReadFile(endpoint.Template)
		if err != nil {
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		w.Write(content)
	}
}
