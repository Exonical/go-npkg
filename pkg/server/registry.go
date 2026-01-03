package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/Exonical/go-npkg/types"
)

// RegistryConfig holds registry configuration
type RegistryConfig struct {
	StorageDir     string
	EnableAuth     bool
	AllowAnonymous bool
}

// Registry represents the NPM registry server
type Registry struct {
	packages    map[string]*types.Package
	tarballs    map[string][]byte
	authManager *AuthManager
	config      RegistryConfig
	mu          sync.RWMutex
}

// NewRegistry creates a new registry instance
func NewRegistry() *Registry {
	return &Registry{
		packages:    make(map[string]*types.Package),
		tarballs:    make(map[string][]byte),
		authManager: NewAuthManager(),
		config: RegistryConfig{
			StorageDir:     "./storage",
			EnableAuth:     true,
			AllowAnonymous: true,
		},
	}
}

// NewRegistryWithConfig creates a new registry with custom configuration
func NewRegistryWithConfig(config RegistryConfig) *Registry {
	r := NewRegistry()
	r.config = config
	return r
}

// Start starts the registry server on the given port
func (r *Registry) Start(port string) error {
	mux := http.NewServeMux()

	// Ensure storage directory exists
	if err := os.MkdirAll(r.config.StorageDir, 0755); err != nil {
		return fmt.Errorf("failed to create storage directory: %w", err)
	}

	// Register routes
	mux.HandleFunc("/", r.handleRoot)
	mux.HandleFunc("/-/ping", r.handlePing)
	mux.HandleFunc("/-/v1/search", r.handleSearch)
	mux.HandleFunc("/-/user/", r.handleUser)
	mux.HandleFunc("/package/", r.handlePackage)

	log.Printf("Starting NPM registry server on port %s", port)
	return http.ListenAndServe(":"+port, mux)
}

// handleRoot returns registry information
func (r *Registry) handleRoot(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	info := types.RegistryInfo{
		DBName:    "npm-registry",
		DBVersion: "1.0.0",
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

// handlePing responds to health checks
func (r *Registry) handlePing(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{}`))
}

// handlePackage handles package-related requests
func (r *Registry) handlePackage(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		r.handleGetPackage(w, req)
	case http.MethodPut:
		r.handlePublishPackage(w, req)
	case http.MethodDelete:
		r.handleDeletePackage(w, req)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetPackage handles package metadata requests
func (r *Registry) handleGetPackage(w http.ResponseWriter, req *http.Request) {
	// Extract package name from URL
	urlPath := strings.TrimPrefix(req.URL.Path, "/package/")
	parts := strings.Split(urlPath, "/")
	packageName := parts[0]

	if packageName == "" {
		// List all packages
		r.listPackages(w, req)
		return
	}

	pkg, exists := r.packages[packageName]
	if !exists {
		http.Error(w, "Package not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pkg)
}

// handlePublishPackage handles package publishing
func (r *Registry) handlePublishPackage(w http.ResponseWriter, req *http.Request) {
	// Extract package name from URL
	urlPath := strings.TrimPrefix(req.URL.Path, "/package/")
	parts := strings.Split(urlPath, "/")
	packageName := parts[0]

	if packageName == "" {
		http.Error(w, "Package name required", http.StatusBadRequest)
		return
	}

	var pkg types.Package
	if err := json.NewDecoder(req.Body).Decode(&pkg); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Store the package
	r.packages[packageName] = &pkg

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"ok":  "true",
		"id":  pkg.ID,
		"rev": "1-" + pkg.Version,
	})
}

// listPackages returns a list of all packages
func (r *Registry) listPackages(w http.ResponseWriter, req *http.Request) {
	packages := make([]string, 0, len(r.packages))
	for name := range r.packages {
		packages = append(packages, name)
	}

	response := map[string]interface{}{
		"packages": packages,
		"total":    len(packages),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// handleSearch handles package search requests
func (r *Registry) handleSearch(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := req.URL.Query().Get("text")

	r.mu.RLock()
	defer r.mu.RUnlock()

	var results []types.SearchObject
	for name, pkg := range r.packages {
		// Simple search: check if query matches name, description, or keywords
		if query == "" || matchesSearch(pkg, query) {
			results = append(results, types.SearchObject{
				Package: types.SearchPackage{
					Name:        name,
					Version:     pkg.Version,
					Description: pkg.Description,
					Keywords:    pkg.Keywords,
					Author:      pkg.Author,
				},
				SearchScore: 1.0,
			})
		}
	}

	response := types.SearchResult{
		Objects: results,
		Total:   len(results),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// matchesSearch checks if a package matches the search query
func matchesSearch(pkg *types.Package, query string) bool {
	query = strings.ToLower(query)

	if strings.Contains(strings.ToLower(pkg.Name), query) {
		return true
	}
	if strings.Contains(strings.ToLower(pkg.Description), query) {
		return true
	}
	for _, keyword := range pkg.Keywords {
		if strings.Contains(strings.ToLower(keyword), query) {
			return true
		}
	}
	return false
}

// handleUser handles user authentication requests
func (r *Registry) handleUser(w http.ResponseWriter, req *http.Request) {
	path := strings.TrimPrefix(req.URL.Path, "/-/user/")

	// Handle token logout
	if strings.HasPrefix(path, "token/") {
		r.authManager.HandleLogout(w, req)
		return
	}

	// Handle login/register
	if strings.HasPrefix(path, "org.couchdb.user:") {
		r.authManager.HandleLogin(w, req)
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
}

// handleDeletePackage handles package deletion
func (r *Registry) handleDeletePackage(w http.ResponseWriter, req *http.Request) {
	urlPath := strings.TrimPrefix(req.URL.Path, "/package/")
	parts := strings.Split(urlPath, "/")
	packageName := parts[0]

	if packageName == "" {
		http.Error(w, "Package name required", http.StatusBadRequest)
		return
	}

	// Check authentication
	if r.config.EnableAuth && !r.config.AllowAnonymous {
		authHeader := req.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization required", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if _, err := r.authManager.ValidateToken(token); err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.packages[packageName]; !exists {
		http.Error(w, "Package not found", http.StatusNotFound)
		return
	}

	delete(r.packages, packageName)

	// Delete associated tarballs
	for key := range r.tarballs {
		if strings.HasPrefix(key, packageName+"/") {
			delete(r.tarballs, key)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}
