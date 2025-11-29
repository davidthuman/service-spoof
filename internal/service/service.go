package service

import (
	"net/http"

	"github.com/davidthuman/service-spoof/internal/config"
)

// Service represents a spoofable service
type Service interface {
	// Name returns the service identifier
	Name() string

	// Type returns the service type
	Type() string

	// Headers returns default headers for this service
	Headers() map[string]string

	// Router returns the endpoint router for this service
	Router() *Router

	// HandleRequest handles the HTTP request
	HandleRequest(w http.ResponseWriter, r *http.Request)
}

// NewService creates a new service from configuration
func NewService(cfg *config.ServiceConfig) (Service, error) {
	switch cfg.Type {
	case "apache2":
		return NewApache2Service(cfg)
	case "nginx":
		return NewNginxService(cfg)
	case "wordpress":
		return NewWordPressService(cfg)
	case "iis":
		return NewIISService(cfg)
	default:
		return NewGenericService(cfg)
	}
}
