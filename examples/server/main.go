// Example: Basic npm registry server
//
// This example demonstrates:
//   - Per-uplink configuration (caching, TTL, auth)
//   - Package rules for routing packages to specific uplinks
//   - TTL-based cache invalidation
//   - Singleflight request coalescing
//
// Usage:
//
//	go run main.go
//	go run main.go -port 4873 -storage ./my-storage
//	go run main.go -maxage 5m  # 5 minute metadata TTL
package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/Exonical/go-npkg/server"
	"github.com/Exonical/go-npkg/uplink"
)

func main() {
	port := flag.String("port", "", "Port to listen on (default: 4873)")
	storageDir := flag.String("storage", "./storage", "Storage directory for packages")
	baseURL := flag.String("url", "", "Base URL for the registry (default: http://localhost:<port>)")
	cacheTarballs := flag.Bool("cache", true, "Cache tarballs from uplinks")
	maxAge := flag.Duration("maxage", 2*time.Minute, "Metadata cache TTL (e.g., 2m, 30s, 1h)")
	flag.Parse()

	// Use PORT env var if flag not set
	if *port == "" {
		*port = os.Getenv("PORT")
		if *port == "" {
			*port = "4873"
		}
	}

	// Default base URL
	if *baseURL == "" {
		*baseURL = "http://localhost:" + *port
	}

	// Create npmjs uplink with per-uplink settings
	npmjs := uplink.New(uplink.Config{
		Name:          "npmjs",
		URL:           "https://registry.npmjs.org",
		CacheTarballs: *cacheTarballs,
		MaxAge:        *maxAge, // Metadata TTL for cache invalidation
		// Auth: &uplink.AuthConfig{Type: "bearer", Token: "your-token"}, // Optional auth
	})

	// Example: Package rules for routing
	// Uncomment to enable selective proxying:
	//
	// packageRules := []server.PackageRule{
	//     {Pattern: "@mycompany/*", Proxy: []string{}},           // Local only (no proxy)
	//     {Pattern: "@internal/*", Proxy: []string{"private"}},   // Route to private uplink
	//     {Pattern: "**", Proxy: []string{"npmjs"}},              // Everything else to npmjs
	// }

	config := server.HybridConfig{
		StorageDir: *storageDir,
		BaseURL:    *baseURL,
		Uplinks:    []*uplink.Uplink{npmjs},
		// PackageRules: packageRules, // Uncomment to enable package rules
	}

	registry, err := server.NewHybridRegistry(config)
	if err != nil {
		log.Fatal("Failed to create registry:", err)
	}

	log.Printf("NPM Registry")
	log.Printf("  Storage: %s", *storageDir)
	log.Printf("  Base URL: %s", *baseURL)
	log.Printf("  Cache tarballs: %v", *cacheTarballs)
	log.Printf("  Metadata TTL: %v", *maxAge)
	log.Println()
	log.Printf("Features:")
	log.Printf("  - Singleflight request coalescing (prevents thundering herd)")
	log.Printf("  - TTL-based cache invalidation")
	log.Printf("  - Raw packument caching (URLs rewritten on response)")
	log.Println()
	log.Printf("Usage:")
	log.Printf("  npm set registry %s", *baseURL)
	log.Printf("  npm install <package>")
	log.Printf("  npm publish")
	log.Println()

	if err := registry.Start(*port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
