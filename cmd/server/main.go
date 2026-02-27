package main

import (
	"fmt"
	"log"
	"os"

	"gotunnel/internal/server"
)

func main() {
	// Load .env file if it exists
	server.LoadDotEnv(".env")

	config := server.LoadConfig()

	fmt.Println("╔══════════════════════════════════════╗")
	fmt.Println("║         GoTunnel Server v1.0         ║")
	fmt.Println("╚══════════════════════════════════════╝")
	fmt.Println()

	srv, err := server.New(config)
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
		os.Exit(1)
	}

	if err := srv.StartServers(); err != nil {
		log.Fatalf("Server error: %v", err)
		os.Exit(1)
	}
}
