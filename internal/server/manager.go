package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/davidthuman/service-spoof/internal/config"
	"github.com/davidthuman/service-spoof/internal/database"
	"github.com/davidthuman/service-spoof/internal/middleware"
	"github.com/davidthuman/service-spoof/internal/service"
)

// Manager manages multiple HTTP servers across different ports
type Manager struct {
	servers  map[int]*http.Server
	services map[int][]service.Service
	logger   *database.RequestLogger
	config   *config.Config
}

// NewManager creates a new server manager
func NewManager(cfg *config.Config, logger *database.RequestLogger) (*Manager, error) {
	m := &Manager{
		servers:  make(map[int]*http.Server),
		services: make(map[int][]service.Service),
		logger:   logger,
		config:   cfg,
	}

	// Build port-to-service mapping
	portMap := cfg.GetServicesByPort()

	// Create services and servers for each port
	for port, serviceCfgs := range portMap {
		services := make([]service.Service, 0)

		// Create service instances
		for _, svcCfg := range serviceCfgs {
			svc, err := service.NewService(&svcCfg)
			if err != nil {
				return nil, fmt.Errorf("failed to create service %s: %w", svcCfg.Name, err)
			}
			services = append(services, svc)
		}

		m.services[port] = services

		// Create HTTP server for this port
		mux := http.NewServeMux()

		// For now, use the first service for this port
		// In a more complex scenario, you could route based on Host header
		if len(services) > 0 {
			primaryService := services[0]

			// Create middleware chain
			var handler http.Handler = http.HandlerFunc(primaryService.HandleRequest)
			handler = middleware.ServiceHeaders(primaryService)(handler)
			handler = middleware.Logger(logger, primaryService, port)(handler)

			mux.Handle("/", handler)
		}

		m.servers[port] = &http.Server{
			Addr:    fmt.Sprintf(":%d", port),
			Handler: mux,
		}
	}

	return m, nil
}

// Start starts all HTTP servers
func (m *Manager) Start(ctx context.Context) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(m.servers))

	for port, server := range m.servers {
		wg.Add(1)
		go func(port int, srv *http.Server) {
			defer wg.Done()

			log.Printf("Starting server on port %d (services: %v)", port, m.getServiceNames(port))

			// Configure for TLS-based fingerprinting
			listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
			if err != nil {
				errChan <- err
			}
			defer listener.Close()

			// Wrap the listener to intercept connections
			wrappedListener := &middleware.TlsClientHelloListener{listener}

			// Pass connection fingerprint to request
			srv.ConnContext = middleware.ConnContextFingerprint

			if m.config.Tls.CertFilePath != "" {
				err = srv.ServeTLS(wrappedListener, m.config.Tls.CertFilePath, m.config.Tls.KeyFilePath)
			} else {
				err = srv.Serve(wrappedListener)
			}

			if err != nil && err != http.ErrServerClosed {
				errChan <- fmt.Errorf("server on port %d failed: %w", port, err)
			}
		}(port, server)
	}

	// Wait for context cancellation or error
	go func() {
		wg.Wait()
		close(errChan)
	}()

	// Return first error if any
	for err := range errChan {
		return err
	}

	return nil
}

// Shutdown gracefully shuts down all servers
func (m *Manager) Shutdown(ctx context.Context) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(m.servers))

	for port, server := range m.servers {
		wg.Add(1)
		go func(port int, srv *http.Server) {
			defer wg.Done()

			log.Printf("Shutting down server on port %d", port)

			if err := srv.Shutdown(ctx); err != nil {
				errChan <- fmt.Errorf("failed to shutdown server on port %d: %w", port, err)
			}
		}(port, server)
	}

	go func() {
		wg.Wait()
		close(errChan)
	}()

	// Collect all errors
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return fmt.Errorf("shutdown errors: %v", errors)
	}

	return nil
}

// GetPortServiceMap returns a mapping of ports to service names
func (m *Manager) GetPortServiceMap() map[int][]string {
	result := make(map[int][]string)
	for port := range m.services {
		result[port] = m.getServiceNames(port)
	}
	return result
}

func (m *Manager) getServiceNames(port int) []string {
	names := make([]string, 0)
	for _, svc := range m.services[port] {
		names = append(names, svc.Name())
	}
	return names
}
