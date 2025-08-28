package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/evidenceledger/certauth/internal/server"
)

func main() {
	// Initialize logging
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	// Get admin password from environment or command line
	adminPassword := os.Getenv("CERTAUTH_ADMIN_PASSWORD")
	if adminPassword == "" {
		slog.Error("Admin password required. Set CERTAUTH_ADMIN_PASSWORD environment variable")
		os.Exit(1)
	}

	// Create and start server
	srv := server.New(adminPassword)

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		slog.Info("Shutdown signal received")
		cancel()
	}()

	// Start server
	if err := srv.Start(ctx); err != nil {
		slog.Error("Server failed", "error", err)
		os.Exit(1)
	}
}
