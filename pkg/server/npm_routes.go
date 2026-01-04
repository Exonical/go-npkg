package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/Exonical/go-npkg/pkg/semver"
	"github.com/Exonical/go-npkg/pkg/storage"
	"github.com/Exonical/go-npkg/pkg/uplink"
	"golang.org/x/sync/singleflight"
)

// HybridRegistry is an npm-compatible registry with uplink support.
// Authentication is intentionally not built-in; developers should add their own
// middleware or wrap the handler to implement auth as needed.
type HybridRegistry struct {
	storage        *storage.Storage
	uplinks        []*uplink.Uplink
	config         HybridConfig
	baseURL        string
	packumentGroup singleflight.Group // Coalesces concurrent packument fetches
}

// HybridConfig holds hybrid registry configuration
type HybridConfig struct {
	StorageDir   string           // Directory for package storage
	BaseURL      string           // Base URL for tarball rewrites (e.g., "http://localhost:4873")
	Uplinks      []*uplink.Uplink // Upstream registries (default: npmjs.org)
	PackageRules []PackageRule    // Package access rules
}

// PackageRule defines access rules for packages matching a pattern.
// Patterns use glob/minimatch syntax (e.g., "@scope/*", "**", "lodash").
type PackageRule struct {
	Pattern string   // Glob pattern to match package names
	Proxy   []string // Names of uplinks to use for this pattern (empty = local only)
}

// getUplinksForPackage returns the uplinks to use for a given package name.
// If PackageRules are configured, it matches the package name against rules.
// Otherwise, it returns all configured uplinks.
func (hr *HybridRegistry) getUplinksForPackage(name string) []*uplink.Uplink {
	if len(hr.config.PackageRules) == 0 {
		return hr.uplinks
	}

	// Find matching rule (first match wins)
	for _, rule := range hr.config.PackageRules {
		if matchPattern(rule.Pattern, name) {
			if len(rule.Proxy) == 0 {
				// No proxy = local only
				return nil
			}
			// Return uplinks matching the proxy names
			var matched []*uplink.Uplink
			for _, proxyName := range rule.Proxy {
				for _, u := range hr.uplinks {
					if u.Name == proxyName {
						matched = append(matched, u)
						break
					}
				}
			}
			return matched
		}
	}

	// No rule matched - default to all uplinks (catch-all '**')
	return hr.uplinks
}

// fetchPackumentFromUplinks fetches a packument from uplinks with singleflight coalescing.
// This prevents thundering herd when multiple concurrent requests hit the same uncached package.
func (hr *HybridRegistry) fetchPackumentFromUplinks(name string) (*uplink.Packument, error) {
	result, err, _ := hr.packumentGroup.Do(name, func() (interface{}, error) {
		for _, u := range hr.getUplinksForPackage(name) {
			packument, err := u.GetPackument(name)
			if err == nil {
				// Cache the raw packument (with original upstream tarball URLs)
				if saveErr := hr.storage.SavePackument(packument); saveErr != nil {
					log.Printf("Failed to cache packument for %s: %v", name, saveErr)
				}
				return packument, nil
			}
			if err != uplink.ErrNotFound {
				log.Printf("Uplink %s error for %s: %v", u.Name, name, err)
			}
		}
		return nil, uplink.ErrNotFound
	})

	if err != nil {
		return nil, err
	}
	return result.(*uplink.Packument), nil
}

// matchPattern matches a package name against a glob pattern.
// Supports: exact match, "*" (single segment), "**" (any), "@scope/*" (scoped packages).
func matchPattern(pattern, name string) bool {
	// Exact match
	if pattern == name {
		return true
	}

	// "**" matches everything
	if pattern == "**" {
		return true
	}

	// "@*/*" matches all scoped packages
	if pattern == "@*/*" && strings.HasPrefix(name, "@") {
		return true
	}

	// Handle scoped package patterns like "@scope/*"
	if strings.HasPrefix(pattern, "@") && strings.HasSuffix(pattern, "/*") {
		scope := strings.TrimSuffix(pattern, "/*")
		if strings.HasPrefix(name, scope+"/") {
			return true
		}
	}

	// Handle prefix patterns like "my-company-*"
	if strings.HasSuffix(pattern, "*") && !strings.Contains(pattern, "/") {
		prefix := strings.TrimSuffix(pattern, "*")
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	return false
}

// NewHybridRegistry creates a new hybrid registry
func NewHybridRegistry(config HybridConfig) (*HybridRegistry, error) {
	store, err := storage.New(config.StorageDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = "http://localhost:4873"
	}

	uplinksList := config.Uplinks
	if len(uplinksList) == 0 {
		uplinksList = []*uplink.Uplink{uplink.NewNpmjs()}
	}

	return &HybridRegistry{
		storage: store,
		uplinks: uplinksList,
		config:  config,
		baseURL: strings.TrimSuffix(baseURL, "/"),
	}, nil
}

// AddUplink adds an upstream registry
func (hr *HybridRegistry) AddUplink(u *uplink.Uplink) {
	hr.uplinks = append(hr.uplinks, u)
}

// ServeHTTP implements http.Handler, allowing the registry to be used with any router.
func (hr *HybridRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Route requests
	switch {
	case path == "/-/ping":
		hr.handlePing(w, r)
	case path == "/-/whoami":
		hr.handleWhoami(w, r)
	case path == "/-/v1/search":
		hr.handleSearch(w, r)
	case strings.HasPrefix(path, "/-/user/"):
		hr.handleUser(w, r)
	default:
		hr.handlePackageRoutes(w, r)
	}
}

// Start starts the hybrid registry server on the given port.
// For more control, use the registry as an http.Handler directly.
func (hr *HybridRegistry) Start(port string) error {
	log.Printf("Starting hybrid NPM registry on port %s", port)
	log.Printf("Base URL: %s", hr.baseURL)
	return http.ListenAndServe(":"+port, hr)
}

// handlePing responds to npm ping
func (hr *HybridRegistry) handlePing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{}`))
}

// handleWhoami returns the current user.
// Since auth is not built-in, this always returns "anonymous".
// Wrap the handler with auth middleware to provide real user info.
func (hr *HybridRegistry) handleWhoami(w http.ResponseWriter, r *http.Request) {
	// Check for user set by external auth middleware
	user := r.Header.Get("X-Auth-User")
	if user == "" {
		user = "anonymous"
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"username": user})
}

// handleSearch handles package search
func (hr *HybridRegistry) handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("text")

	// Try uplinks for search
	for _, u := range hr.uplinks {
		result, err := u.Search(query, 20)
		if err == nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(result)
			return
		}
	}

	// Return empty result if all uplinks fail
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(uplink.SearchResult{Objects: []uplink.SearchObject{}, Total: 0})
}

// handleUser handles user authentication endpoints.
// Since auth is not built-in, these are stub endpoints that return success.
// Wrap the handler with auth middleware to provide real authentication.
func (hr *HybridRegistry) handleUser(w http.ResponseWriter, r *http.Request) {
	urlPath := strings.TrimPrefix(r.URL.Path, "/-/user/")

	// Token logout - always succeed (no-op without auth)
	if strings.HasPrefix(urlPath, "token/") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}

	// User login/adduser - return a dummy token (no-op without auth)
	if strings.HasPrefix(urlPath, "org.couchdb.user:") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    true,
			"token": "anonymous-token",
		})
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
}

// handlePackageRoutes routes package requests
func (hr *HybridRegistry) handlePackageRoutes(w http.ResponseWriter, r *http.Request) {
	urlPath := r.URL.Path

	// Root path - registry info
	if urlPath == "/" {
		hr.handleRegistryInfo(w, r)
		return
	}

	// Parse the path to determine what's being requested
	// Formats:
	//   /:package (or /@scope%2Fname)
	//   /:package/:version
	//   /:package/-/:filename.tgz

	// URL decode the path for scoped packages
	decodedPath, _ := url.PathUnescape(urlPath)
	decodedPath = strings.TrimPrefix(decodedPath, "/")

	// Check for tarball request (contains /-/)
	if strings.Contains(decodedPath, "/-/") {
		hr.handleTarball(w, r, decodedPath)
		return
	}

	// Split path
	parts := strings.SplitN(decodedPath, "/", 3)

	// Handle scoped packages (@scope/name)
	var pkgName string
	var version string

	if strings.HasPrefix(parts[0], "@") && len(parts) >= 2 {
		// Scoped package: @scope/name or @scope/name/version
		pkgName = parts[0] + "/" + parts[1]
		if len(parts) > 2 {
			version = parts[2]
		}
	} else {
		// Unscoped package: name or name/version
		pkgName = parts[0]
		if len(parts) > 1 {
			version = parts[1]
		}
	}

	switch r.Method {
	case http.MethodGet:
		if version != "" {
			hr.handleGetVersion(w, r, pkgName, version)
		} else {
			hr.handleGetPackument(w, r, pkgName)
		}
	case http.MethodPut:
		hr.handlePublish(w, r, pkgName)
	case http.MethodDelete:
		hr.handleUnpublish(w, r, pkgName)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRegistryInfo returns registry metadata
func (hr *HybridRegistry) handleRegistryInfo(w http.ResponseWriter, r *http.Request) {
	info := map[string]interface{}{
		"db_name":              "npm-registry-go",
		"doc_count":            0,
		"doc_del_count":        0,
		"update_seq":           0,
		"purge_seq":            0,
		"compact_running":      false,
		"disk_size":            0,
		"data_size":            0,
		"instance_start_time":  "0",
		"disk_format_version":  0,
		"committed_update_seq": 0,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

// handleGetPackument returns full package metadata (all versions)
func (hr *HybridRegistry) handleGetPackument(w http.ResponseWriter, r *http.Request, name string) {
	// Try local storage first
	packument, err := hr.storage.GetPackument(name)
	if err == nil {
		// Check if cache is stale based on uplink MaxAge (TTL)
		if !hr.isPackumentStale(name) {
			// Rewrite tarball URLs to point to this registry (on response only)
			hr.rewriteTarballURLs(packument)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(packument)
			return
		}
		// Cache is stale - try to refresh from uplinks, but fall back to cached if uplinks fail
		freshPackument, refreshErr := hr.fetchPackumentFromUplinks(name)
		if refreshErr == nil {
			packument = freshPackument
		}
		// Use packument (fresh or stale) for response
		hr.rewriteTarballURLs(packument)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(packument)
		return
	}

	// Fetch from uplinks with singleflight coalescing (prevents thundering herd)
	packument, err = hr.fetchPackumentFromUplinks(name)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// Rewrite tarball URLs only for the response to client
	hr.rewriteTarballURLs(packument)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(packument)
}

// isPackumentStale checks if a cached packument is older than the configured MaxAge.
// Returns false if no uplinks are configured or if the packument doesn't exist.
func (hr *HybridRegistry) isPackumentStale(name string) bool {
	age, err := hr.storage.GetPackumentAge(name)
	if err != nil {
		return false
	}

	// Use the minimum MaxAge from applicable uplinks
	uplinks := hr.getUplinksForPackage(name)
	if len(uplinks) == 0 {
		return false // No uplinks = local only, never stale
	}

	for _, u := range uplinks {
		if age > u.MaxAge {
			return true
		}
	}
	return false
}

// handleGetVersion returns a specific version
func (hr *HybridRegistry) handleGetVersion(w http.ResponseWriter, r *http.Request, name, version string) {
	// Get full packument first
	packument, err := hr.storage.GetPackument(name)
	if err != nil {
		// Fetch from uplinks with singleflight coalescing
		packument, err = hr.fetchPackumentFromUplinks(name)
	}

	if packument == nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// Handle dist-tag (e.g., "latest")
	if resolvedVersion, ok := packument.DistTags[version]; ok {
		version = resolvedVersion
	}

	// Handle semver range
	if !semver.Valid(version) {
		versions := make([]string, 0, len(packument.Versions))
		for v := range packument.Versions {
			versions = append(versions, v)
		}
		resolved, err := semver.MaxSatisfying(versions, version)
		if err != nil {
			http.Error(w, "No matching version", http.StatusNotFound)
			return
		}
		version = resolved
	}

	ver, ok := packument.Versions[version]
	if !ok {
		http.Error(w, "Version not found", http.StatusNotFound)
		return
	}

	// Rewrite tarball URL
	ver.Dist.Tarball = hr.rewriteTarballURL(name, ver.Dist.Tarball)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ver)
}

// handleTarball serves or proxies tarballs
func (hr *HybridRegistry) handleTarball(w http.ResponseWriter, r *http.Request, decodedPath string) {
	// Parse: @scope/name/-/filename.tgz or name/-/filename.tgz
	idx := strings.Index(decodedPath, "/-/")
	if idx == -1 {
		http.Error(w, "Invalid tarball path", http.StatusBadRequest)
		return
	}

	pkgName := decodedPath[:idx]
	filename := decodedPath[idx+3:]

	// Try local storage first
	reader, err := hr.storage.GetTarball(pkgName, filename)
	if err == nil {
		defer func() { _ = reader.Close() }()
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.Copy(w, reader)
		return
	}

	// Get packument to find original tarball URL
	packument, err := hr.storage.GetPackument(pkgName)
	if err != nil {
		// Fetch from uplinks with singleflight coalescing
		packument, err = hr.fetchPackumentFromUplinks(pkgName)
	}

	if packument == nil {
		http.Error(w, "Package not found", http.StatusNotFound)
		return
	}

	// Find a matching version for this tarball.
	// The packument in storage has original upstream URLs (not rewritten),
	// so we can use them directly for fetching.
	matched := false
	upstreamURL := ""
	for _, ver := range packument.Versions {
		if strings.HasSuffix(ver.Dist.Tarball, filename) || path.Base(ver.Dist.Tarball) == filename {
			matched = true
			// Use the original upstream URL from the cached packument
			if ver.Dist.Tarball != "" {
				upstreamURL = ver.Dist.Tarball
			}
			break
		}
	}

	if !matched {
		http.Error(w, "Tarball not found", http.StatusNotFound)
		return
	}

	// Proxy from uplink based on package rules. If we have an explicit upstream URL, try it first.
	for _, u := range hr.getUplinksForPackage(pkgName) {
		candidateURL := upstreamURL
		if candidateURL == "" {
			candidateURL = fmt.Sprintf("%s/%s/-/%s", strings.TrimSuffix(u.URL, "/"), pkgName, filename)
		}

		body, contentType, err := u.GetTarball(candidateURL)
		if err != nil {
			continue
		}
		defer func() { _ = body.Close() }()

		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		} else {
			w.Header().Set("Content-Type", "application/octet-stream")
		}

		// Cache the tarball if the uplink is configured to cache tarballs.
		// Stream to the client while concurrently writing to storage (no full buffering in memory).
		if u.CacheTarballs {
			pr, pw := io.Pipe()
			saveErrCh := make(chan error, 1)
			go func() {
				saveErrCh <- hr.storage.SaveTarball(pkgName, filename, pr)
				_ = pr.Close()
			}()

			_, copyErr := io.Copy(io.MultiWriter(w, pw), body)
			_ = pw.CloseWithError(copyErr)
			saveErr := <-saveErrCh
			if saveErr != nil {
				log.Printf("Failed to cache tarball %s/%s: %v", pkgName, filename, saveErr)
			}
		} else {
			_, _ = io.Copy(w, body)
		}
		return
	}

	http.Error(w, "Tarball not found", http.StatusNotFound)
}

// handlePublish handles npm publish.
// Note: Authentication should be handled by wrapping middleware, not built into the registry.
func (hr *HybridRegistry) handlePublish(w http.ResponseWriter, r *http.Request, name string) {
	// Parse publish payload
	var payload PublishPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Get or create packument
	packument, err := hr.storage.GetPackument(name)
	if err != nil {
		// New package
		packument = &uplink.Packument{
			ID:       name,
			Name:     name,
			DistTags: make(map[string]string),
			Versions: make(map[string]*uplink.Version),
		}
	}

	// Add new versions
	for version, versionData := range payload.Versions {
		if _, exists := packument.Versions[version]; exists {
			http.Error(w, fmt.Sprintf("Version %s already exists", version), http.StatusConflict)
			return
		}

		// Convert to uplink.Version - marshal maps to json.RawMessage
		scriptsJSON, _ := json.Marshal(versionData.Scripts)
		depsJSON, _ := json.Marshal(versionData.Dependencies)
		devDepsJSON, _ := json.Marshal(versionData.DevDependencies)
		peerDepsJSON, _ := json.Marshal(versionData.PeerDependencies)
		mainJSON, _ := json.Marshal(versionData.Main)

		ver := &uplink.Version{
			Name:             versionData.Name,
			Version:          versionData.Version,
			Description:      versionData.Description,
			Main:             mainJSON,
			Scripts:          scriptsJSON,
			Dependencies:     depsJSON,
			DevDependencies:  devDepsJSON,
			PeerDependencies: peerDepsJSON,
			Dist: uplink.Dist{
				Tarball:   fmt.Sprintf("%s/%s/-/%s-%s.tgz", hr.baseURL, url.PathEscape(name), name, version),
				Shasum:    versionData.Dist.Shasum,
				Integrity: versionData.Dist.Integrity,
			},
		}
		packument.Versions[version] = ver
	}

	// Update dist-tags
	for tag, version := range payload.DistTags {
		packument.DistTags[tag] = version
	}

	// Save attachments (tarballs)
	for filename, attachment := range payload.Attachments {
		data, err := decodeAttachment(attachment.Data)
		if err != nil {
			http.Error(w, "Invalid attachment: "+err.Error(), http.StatusBadRequest)
			return
		}

		if err := hr.storage.SaveTarball(name, filename, bytes.NewReader(data)); err != nil {
			http.Error(w, "Failed to save tarball: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Save packument
	if err := hr.storage.SavePackument(packument); err != nil {
		http.Error(w, "Failed to save package: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"success": true,
	})
}

// handleUnpublish handles npm unpublish.
// Note: Authentication should be handled by wrapping middleware, not built into the registry.
func (hr *HybridRegistry) handleUnpublish(w http.ResponseWriter, r *http.Request, name string) {
	if err := hr.storage.DeletePackument(name); err != nil {
		http.Error(w, "Failed to delete package", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// rewriteTarballURLs rewrites all tarball URLs in a packument
func (hr *HybridRegistry) rewriteTarballURLs(packument *uplink.Packument) {
	for _, ver := range packument.Versions {
		ver.Dist.Tarball = hr.rewriteTarballURL(packument.Name, ver.Dist.Tarball)
	}
}

// rewriteTarballURL rewrites a single tarball URL
func (hr *HybridRegistry) rewriteTarballURL(pkgName, originalURL string) string {
	// Extract filename from original URL
	filename := path.Base(originalURL)
	return fmt.Sprintf("%s/%s/-/%s", hr.baseURL, url.PathEscape(pkgName), filename)
}

// PublishPayload represents the npm publish request body
type PublishPayload struct {
	ID          string                       `json:"_id"`
	Name        string                       `json:"name"`
	Description string                       `json:"description"`
	DistTags    map[string]string            `json:"dist-tags"`
	Versions    map[string]PublishVersion    `json:"versions"`
	Attachments map[string]PublishAttachment `json:"_attachments"`
	Readme      string                       `json:"readme"`
}

// PublishVersion represents a version in publish payload
type PublishVersion struct {
	Name             string            `json:"name"`
	Version          string            `json:"version"`
	Description      string            `json:"description"`
	Main             string            `json:"main"`
	Scripts          map[string]string `json:"scripts"`
	Dependencies     map[string]string `json:"dependencies"`
	DevDependencies  map[string]string `json:"devDependencies"`
	PeerDependencies map[string]string `json:"peerDependencies"`
	Dist             PublishDist       `json:"dist"`
}

// PublishDist represents dist info in publish payload
type PublishDist struct {
	Shasum    string `json:"shasum"`
	Integrity string `json:"integrity"`
}

// PublishAttachment represents an attachment in publish payload
type PublishAttachment struct {
	ContentType string `json:"content_type"`
	Data        string `json:"data"`
	Length      int    `json:"length"`
}

// decodeAttachment decodes base64 attachment data
func decodeAttachment(data string) ([]byte, error) {
	// npm sends base64-encoded tarballs
	return base64.StdEncoding.DecodeString(data)
}
