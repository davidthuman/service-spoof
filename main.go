package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/davidthuman/service-spoof/internal/config"
	"github.com/davidthuman/service-spoof/internal/database"
	"github.com/davidthuman/service-spoof/internal/server"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig("./config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("Loaded configuration version %s", cfg.Version)

	// Initialize database
	db, err := database.New(cfg.Database.Path)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	if err := db.Initialize(); err != nil {
		log.Fatalf("Failed to create database schema: %v", err)
	}

	log.Printf("Database initialized at %s", cfg.Database.Path)

	// Create request logger
	requestLogger := database.NewRequestLogger(db)

	// Create server manager
	manager, err := server.NewManager(cfg, requestLogger)
	if err != nil {
		log.Fatalf("Failed to create server manager: %v", err)
	}

	// Start servers
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := manager.Start(ctx); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	log.Println("Service spoof started successfully")
	portServiceMap := manager.GetPortServiceMap()
	for port, services := range portServiceMap {
		log.Printf("Port %d: %v", port, services)
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := manager.Shutdown(shutdownCtx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}

	log.Println("Shutdown complete")
}
