package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/davidthuman/service-spoof/internal/config"
	"github.com/davidthuman/service-spoof/internal/database"
	"github.com/davidthuman/service-spoof/internal/fingerprint"
	"github.com/davidthuman/service-spoof/internal/middleware"
	"github.com/davidthuman/service-spoof/internal/service"
)

// Manager manages multiple HTTP servers across different ports
type Manager struct {
	servers  map[int]*http.Server
	services map[int][]service.Service
	logger   *database.RequestLogger
	config   *config.Config
	ja4Store *fingerprint.JA4Store
}

// NewManager creates a new server manager
func NewManager(cfg *config.Config, logger *database.RequestLogger) (*Manager, error) {
	m := &Manager{
		servers:  make(map[int]*http.Server),
		services: make(map[int][]service.Service),
		logger:   logger,
		config:   cfg,
	}

	// Initialize JA4 store with 5-minute TTL
	m.ja4Store = fingerprint.NewJA4Store(5 * time.Minute)

	// Configure TLS if certificates are provided
	var tlsConfig *tls.Config
	if cfg.Tls.CertFilePath != "" && cfg.Tls.KeyFilePath != "" {
		cert, err := tls.LoadX509KeyPair(cfg.Tls.CertFilePath, cfg.Tls.KeyFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificates: %w", err)
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				// Generate JA4 fingerprint
				ja4 := fingerprint.GenerateJA4(hello)

				// Store fingerprint keyed by remote address
				if hello.Conn != nil {
					m.ja4Store.Set(hello.Conn.RemoteAddr().String(), ja4)
				}

				// Return nil to use default config
				return nil, nil
			},
		}
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
			handler = middleware.Logger(logger, primaryService, port, m.ja4Store)(handler)

			mux.Handle("/", handler)
		}

		m.servers[port] = &http.Server{
			Addr:      fmt.Sprintf(":%d", port),
			Handler:   mux,
			TLSConfig: tlsConfig,
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

			// Determine if this server should use TLS
			if srv.TLSConfig != nil {
				if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
					errChan <- fmt.Errorf("server on port %d failed: %w", port, err)
				}
			} else {
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					errChan <- fmt.Errorf("server on port %d failed: %w", port, err)
				}
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

	// Close JA4 store cleanup goroutine
	if m.ja4Store != nil {
		m.ja4Store.Close()
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
