// Example: Go client for interacting with the npm registry.
//
// This example demonstrates:
//   - Connecting to a local or remote npm registry
//   - Fetching package metadata (packuments)
//   - Searching for packages
//
// Usage:
//
//	go run main.go
//	REGISTRY_URL=http://localhost:4873 go run main.go
//	go run main.go lodash express react
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/Exonical/go-npkg/pkg/client"
)

func main() {
	registryURL := os.Getenv("REGISTRY_URL")
	if registryURL == "" {
		registryURL = "http://localhost:4873" // Default port
	}

	npmClient := client.New(registryURL)

	// Test registry connectivity
	fmt.Printf("Connecting to registry: %s\n", registryURL)
	if err := npmClient.Ping(); err != nil {
		log.Fatal("Failed to ping registry:", err)
	}
	fmt.Println("✓ Registry is accessible!")

	// Get registry info
	info, err := npmClient.GetRegistryInfo()
	if err != nil {
		log.Printf("Warning: Could not get registry info: %v", err)
	} else {
		fmt.Printf("✓ Registry: %s\n", info.DBName)
	}

	// If package names provided as args, fetch their metadata
	packages := os.Args[1:]
	if len(packages) == 0 {
		packages = []string{"lodash"} // Default example
	}

	fmt.Println()
	for _, pkgName := range packages {
		fmt.Printf("Fetching: %s\n", pkgName)

		pkg, err := npmClient.GetPackage(pkgName)
		if err != nil {
			log.Printf("  ✗ Failed to get %s: %v", pkgName, err)
			continue
		}

		fmt.Printf("  ✓ %s v%s\n", pkg.Name, pkg.Version)
		if pkg.Description != "" {
			fmt.Printf("    Description: %s\n", pkg.Description)
		}
		if pkg.Author != nil && pkg.Author.Name != "" {
			fmt.Printf("    Author: %s\n", pkg.Author.Name)
		}
		if pkg.License != "" {
			fmt.Printf("    License: %s\n", pkg.License)
		}
	}

	// Search example
	fmt.Println()
	fmt.Println("Searching for 'react'...")
	results, err := npmClient.Search("react", 10)
	if err != nil {
		log.Printf("Search failed: %v", err)
	} else if results != nil && len(results.Objects) > 0 {
		fmt.Printf("Found %d results\n", len(results.Objects))
		for i, obj := range results.Objects {
			if i >= 5 {
				fmt.Printf("  ... and %d more\n", len(results.Objects)-5)
				break
			}
			fmt.Printf("  - %s: %s\n", obj.Package.Name, obj.Package.Description)
		}
	}
}
