package service

import (
	"path/filepath"
)

// Router handles endpoint matching for a service
type Router struct {
	endpoints []*Endpoint
}

// Endpoint represents a single endpoint configuration
type Endpoint struct {
	Path     string
	Method   string
	Status   int
	Template string
	Headers  map[string]string
}

// NewRouter creates a new router
func NewRouter() *Router {
	return &Router{
		endpoints: make([]*Endpoint, 0),
	}
}

// AddEndpoint adds an endpoint to the router
func (r *Router) AddEndpoint(ep *Endpoint) {
	r.endpoints = append(r.endpoints, ep)
}

// Match finds the first matching endpoint for the given method and path
// Priority: exact match > pattern match > wildcard match
func (r *Router) Match(method, path string) (*Endpoint, bool) {
	var wildcardMatch *Endpoint

	for _, ep := range r.endpoints {
		// Check method match
		if ep.Method != "*" && ep.Method != method {
			continue
		}

		// Exact path match - return immediately
		if ep.Path == path {
			return ep, true
		}

		// Wildcard match - save but continue looking for exact/pattern match
		if ep.Path == "/*" || ep.Path == "*" {
			if wildcardMatch == nil {
				wildcardMatch = ep
			}
			continue
		}

		// Pattern matching (e.g., /admin/*, *.php)
		if matched, _ := filepath.Match(ep.Path, path); matched {
			return ep, true
		}
	}

	// Return wildcard match if no exact or pattern match found
	if wildcardMatch != nil {
		return wildcardMatch, true
	}

	return nil, false
}
