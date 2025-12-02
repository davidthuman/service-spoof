package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// Config represents the main configuration structure
type Config struct {
	Version  string          `yaml:"version"`
	Database DatabaseConfig  `yaml:"database"`
	Tls      TlsConfig       `yaml:"tls"`
	Services []ServiceConfig `yaml:"services"`
}

// DatabaseConfig holds database-related configuration
type DatabaseConfig struct {
	Path string `yaml:"path"`
}

// TlsConfig holds tls-related configuration
type TlsConfig struct {
	CertFilePath string `yaml:"certFilePath"`
	KeyFilePath  string `yaml:"keyFilePath"`
}

// ServiceConfig represents a single service configuration
type ServiceConfig struct {
	Name      string            `yaml:"name"`
	Type      string            `yaml:"type"`
	Enabled   bool              `yaml:"enabled"`
	Ports     []int             `yaml:"ports"`
	Headers   map[string]string `yaml:"headers"`
	Endpoints []EndpointConfig  `yaml:"endpoints"`
}

// EndpointConfig represents a single endpoint within a service
type EndpointConfig struct {
	Path     string            `yaml:"path"`
	Method   string            `yaml:"method"`
	Status   int               `yaml:"status"`
	Template string            `yaml:"template"`
	Headers  map[string]string `yaml:"headers"`
}

// LoadConfig loads and parses the YAML configuration file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Database.Path == "" {
		return fmt.Errorf("database.path is required")
	}

	if len(c.Services) == 0 {
		return fmt.Errorf("at least one service must be defined")
	}

	for i, svc := range c.Services {
		if svc.Name == "" {
			return fmt.Errorf("service[%d]: name is required", i)
		}
		if svc.Type == "" {
			return fmt.Errorf("service[%d]: type is required", i)
		}
		if len(svc.Ports) == 0 {
			return fmt.Errorf("service[%d]: at least one port is required", i)
		}
		if len(svc.Endpoints) == 0 {
			return fmt.Errorf("service[%d]: at least one endpoint is required", i)
		}

		for j, ep := range svc.Endpoints {
			if ep.Path == "" {
				return fmt.Errorf("service[%d].endpoint[%d]: path is required", i, j)
			}
			if ep.Method == "" {
				return fmt.Errorf("service[%d].endpoint[%d]: method is required", i, j)
			}
			if ep.Status == 0 {
				return fmt.Errorf("service[%d].endpoint[%d]: status is required", i, j)
			}
		}
	}

	return nil
}

// GetEnabledServices returns only the enabled services
func (c *Config) GetEnabledServices() []ServiceConfig {
	enabled := make([]ServiceConfig, 0)
	for _, svc := range c.Services {
		if svc.Enabled {
			enabled = append(enabled, svc)
		}
	}
	return enabled
}

// GetServicesByPort creates a mapping of ports to services
func (c *Config) GetServicesByPort() map[int][]ServiceConfig {
	portMap := make(map[int][]ServiceConfig)
	for _, svc := range c.GetEnabledServices() {
		for _, port := range svc.Ports {
			portMap[port] = append(portMap[port], svc)
		}
	}
	return portMap
}
