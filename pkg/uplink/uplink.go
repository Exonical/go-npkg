package uplink

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Uplink represents an upstream npm registry
type Uplink struct {
	Name          string
	URL           string
	Timeout       time.Duration
	MaxRetries    int
	Headers       map[string]string
	CacheTarballs bool          // Whether to cache tarballs from this uplink
	MaxAge        time.Duration // Metadata cache TTL (0 = use default 2min)
	Auth          *AuthConfig   // Auth config for upstream
	httpClient    *http.Client
}

// Config holds uplink configuration
type Config struct {
	Name          string            `json:"name" yaml:"name"`
	URL           string            `json:"url" yaml:"url"`
	Timeout       time.Duration     `json:"timeout" yaml:"timeout"`
	MaxRetries    int               `json:"maxRetries" yaml:"maxRetries"`
	Headers       map[string]string `json:"headers" yaml:"headers"`
	CacheTarballs bool              `json:"cache" yaml:"cache"`   // cache (default true)
	MaxAge        time.Duration     `json:"maxage" yaml:"maxage"` // maxage for metadata TTL
	Auth          *AuthConfig       `json:"auth" yaml:"auth"`     // Auth for upstream registry
}

// AuthConfig holds authentication configuration for upstream registries
type AuthConfig struct {
	Type     string `json:"type" yaml:"type"`         // "bearer" or "basic"
	Token    string `json:"token" yaml:"token"`       // Bearer token
	Username string `json:"username" yaml:"username"` // Basic auth username
	Password string `json:"password" yaml:"password"` // Basic auth password
}

// Packument represents the full npm package document (all versions)
type Packument struct {
	ID           string              `json:"_id"`
	Name         string              `json:"name"`
	Description  string              `json:"description,omitempty"`
	DistTags     map[string]string   `json:"dist-tags"`
	Versions     map[string]*Version `json:"versions"`
	Time         map[string]string   `json:"time,omitempty"`
	Author       json.RawMessage     `json:"author,omitempty"`
	Maintainers  json.RawMessage     `json:"maintainers,omitempty"`
	Repository   json.RawMessage     `json:"repository,omitempty"`
	Readme       string              `json:"readme,omitempty"`
	ReadmeFile   string              `json:"readmeFilename,omitempty"`
	Homepage     string              `json:"homepage,omitempty"`
	Keywords     json.RawMessage     `json:"keywords,omitempty"`
	Bugs         json.RawMessage     `json:"bugs,omitempty"`
	License      json.RawMessage     `json:"license,omitempty"`
	Users        json.RawMessage     `json:"users,omitempty"`
	Contributors json.RawMessage     `json:"contributors,omitempty"`
}

// Version represents a single package version.
// Many fields use json.RawMessage to handle npm's inconsistent JSON schemas
// where fields can be strings, objects, or arrays depending on the package.
type Version struct {
	Name                 string          `json:"name"`
	Version              string          `json:"version"`
	Description          string          `json:"description,omitempty"`
	Main                 json.RawMessage `json:"main,omitempty"`
	Scripts              json.RawMessage `json:"scripts,omitempty"`
	Dependencies         json.RawMessage `json:"dependencies,omitempty"`
	DevDependencies      json.RawMessage `json:"devDependencies,omitempty"`
	PeerDependencies     json.RawMessage `json:"peerDependencies,omitempty"`
	OptionalDependencies json.RawMessage `json:"optionalDependencies,omitempty"`
	BundleDependencies   json.RawMessage `json:"bundleDependencies,omitempty"`
	BundledDependencies  json.RawMessage `json:"bundledDependencies,omitempty"`
	Engines              json.RawMessage `json:"engines,omitempty"`
	Author               json.RawMessage `json:"author,omitempty"`
	Contributors         json.RawMessage `json:"contributors,omitempty"`
	Maintainers          json.RawMessage `json:"maintainers,omitempty"`
	Repository           json.RawMessage `json:"repository,omitempty"`
	Keywords             json.RawMessage `json:"keywords,omitempty"`
	Bugs                 json.RawMessage `json:"bugs,omitempty"`
	Homepage             string          `json:"homepage,omitempty"`
	License              json.RawMessage `json:"license,omitempty"`
	Licenses             json.RawMessage `json:"licenses,omitempty"`
	Dist                 Dist            `json:"dist"`
	Deprecated           json.RawMessage `json:"deprecated,omitempty"`
	ID                   string          `json:"_id,omitempty"`
	NpmVersion           string          `json:"_npmVersion,omitempty"`
	NodeVersion          string          `json:"_nodeVersion,omitempty"`
	NpmUser              json.RawMessage `json:"_npmUser,omitempty"`
	HasShrinkwrap        bool            `json:"_hasShrinkwrap,omitempty"`
	Bin                  json.RawMessage `json:"bin,omitempty"`
	Man                  json.RawMessage `json:"man,omitempty"`
	Directories          json.RawMessage `json:"directories,omitempty"`
	Files                json.RawMessage `json:"files,omitempty"`
	Browser              json.RawMessage `json:"browser,omitempty"`
	Module               string          `json:"module,omitempty"`
	Types                string          `json:"types,omitempty"`
	Typings              string          `json:"typings,omitempty"`
	Exports              json.RawMessage `json:"exports,omitempty"`
	Sideeffects          json.RawMessage `json:"sideEffects,omitempty"`
	Cpu                  json.RawMessage `json:"cpu,omitempty"`
	Os                   json.RawMessage `json:"os,omitempty"`
}

// Dist represents distribution info for a version
type Dist struct {
	Tarball      string      `json:"tarball"`
	Shasum       string      `json:"shasum"`
	Integrity    string      `json:"integrity,omitempty"`
	FileCount    int         `json:"fileCount,omitempty"`
	UnpackedSize int64       `json:"unpackedSize,omitempty"`
	Signatures   []Signature `json:"signatures,omitempty"`
}

// Signature represents an npm signature
type Signature struct {
	Keyid string `json:"keyid"`
	Sig   string `json:"sig"`
}

// Person represents author/maintainer info
type Person struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	URL   string `json:"url,omitempty"`
}

// Repository represents repository info
type Repository struct {
	Type string `json:"type,omitempty"`
	URL  string `json:"url,omitempty"`
}

// Bugs represents bug tracking info
type Bugs struct {
	URL   string `json:"url,omitempty"`
	Email string `json:"email,omitempty"`
}

// DefaultMaxAge is the default metadata cache TTL (2 minutes)
const DefaultMaxAge = 2 * time.Minute

// New creates a new uplink client
func New(config Config) *Uplink {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	maxRetries := config.MaxRetries
	if maxRetries == 0 {
		maxRetries = 3
	}

	maxAge := config.MaxAge
	if maxAge == 0 {
		maxAge = DefaultMaxAge
	}

	// Default CacheTarballs to true (default)
	cacheTarballs := true
	if !config.CacheTarballs {
		// Only disable if explicitly set to false in a non-zero Config
		// This is a bit tricky with Go zero values; we'll use a pointer or explicit field later
		// For now, we check if the config was explicitly provided
		cacheTarballs = config.CacheTarballs
	}
	// Actually, since bool zero is false, we need different logic:
	// If URL is set (config is real), use the value; otherwise default true
	if config.URL != "" {
		cacheTarballs = config.CacheTarballs
	} else {
		cacheTarballs = true
	}

	return &Uplink{
		Name:          config.Name,
		URL:           strings.TrimSuffix(config.URL, "/"),
		Timeout:       timeout,
		MaxRetries:    maxRetries,
		Headers:       config.Headers,
		CacheTarballs: cacheTarballs,
		MaxAge:        maxAge,
		Auth:          config.Auth,
		httpClient:    &http.Client{Timeout: timeout},
	}
}

// applyAuth applies authentication headers to a request based on uplink config
func (u *Uplink) applyAuth(req *http.Request) {
	if u.Auth == nil {
		return
	}
	switch u.Auth.Type {
	case "bearer":
		if u.Auth.Token != "" {
			req.Header.Set("Authorization", "Bearer "+u.Auth.Token)
		}
	case "basic":
		if u.Auth.Username != "" {
			req.SetBasicAuth(u.Auth.Username, u.Auth.Password)
		}
	}
}

// NewNpmjs creates an uplink to the official npm registry
func NewNpmjs() *Uplink {
	return New(Config{
		Name:          "npmjs",
		URL:           "https://registry.npmjs.org",
		Timeout:       30 * time.Second,
		CacheTarballs: true,
		MaxAge:        DefaultMaxAge,
	})
}

// GetPackument fetches the full package document (all versions)
func (u *Uplink) GetPackument(name string) (*Packument, error) {
	pkgURL := fmt.Sprintf("%s/%s", u.URL, url.PathEscape(name))

	req, err := http.NewRequest(http.MethodGet, pkgURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "npm-registry-go/1.0.0")
	u.applyAuth(req)

	for k, v := range u.Headers {
		req.Header.Set(k, v)
	}

	var lastErr error
	for attempt := 0; attempt < u.MaxRetries; attempt++ {
		resp, err := u.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode == http.StatusNotFound {
			_ = resp.Body.Close()
			return nil, ErrNotFound
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("upstream returned status %d", resp.StatusCode)
			continue
		}

		var packument Packument
		if err := json.NewDecoder(resp.Body).Decode(&packument); err != nil {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("failed to decode packument: %w", err)
			continue
		}
		_ = resp.Body.Close()

		return &packument, nil
	}

	return nil, fmt.Errorf("failed after %d retries: %w", u.MaxRetries, lastErr)
}

// GetVersion fetches a specific version of a package
func (u *Uplink) GetVersion(name, version string) (*Version, error) {
	pkgURL := fmt.Sprintf("%s/%s/%s", u.URL, url.PathEscape(name), url.PathEscape(version))

	req, err := http.NewRequest(http.MethodGet, pkgURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "npm-registry-go/1.0.0")
	u.applyAuth(req)

	for k, v := range u.Headers {
		req.Header.Set(k, v)
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch version: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream returned status %d", resp.StatusCode)
	}

	var ver Version
	if err := json.NewDecoder(resp.Body).Decode(&ver); err != nil {
		return nil, fmt.Errorf("failed to decode version: %w", err)
	}

	return &ver, nil
}

// GetTarball fetches a package tarball
func (u *Uplink) GetTarball(tarballURL string) (io.ReadCloser, string, error) {
	req, err := http.NewRequest(http.MethodGet, tarballURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "npm-registry-go/1.0.0")
	u.applyAuth(req)

	for k, v := range u.Headers {
		req.Header.Set(k, v)
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch tarball: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		_ = resp.Body.Close()
		return nil, "", ErrNotFound
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, "", fmt.Errorf("upstream returned status %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	return resp.Body, contentType, nil
}

// Search searches for packages
func (u *Uplink) Search(query string, size int) (*SearchResult, error) {
	searchURL := fmt.Sprintf("%s/-/v1/search?text=%s&size=%d", u.URL, url.QueryEscape(query), size)

	req, err := http.NewRequest(http.MethodGet, searchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "npm-registry-go/1.0.0")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to search: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("search returned status %d", resp.StatusCode)
	}

	var result SearchResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode search results: %w", err)
	}

	return &result, nil
}

// SearchResult represents npm search results
type SearchResult struct {
	Objects []SearchObject `json:"objects"`
	Total   int            `json:"total"`
	Time    string         `json:"time"`
}

// SearchObject represents a single search result
type SearchObject struct {
	Package     SearchPackage `json:"package"`
	Score       Score         `json:"score"`
	SearchScore float64       `json:"searchScore"`
}

// SearchPackage represents package info in search results
type SearchPackage struct {
	Name        string   `json:"name"`
	Scope       string   `json:"scope,omitempty"`
	Version     string   `json:"version"`
	Description string   `json:"description,omitempty"`
	Keywords    []string `json:"keywords,omitempty"`
	Date        string   `json:"date,omitempty"`
	Author      *Person  `json:"author,omitempty"`
	Publisher   *Person  `json:"publisher,omitempty"`
	Maintainers []Person `json:"maintainers,omitempty"`
	Links       Links    `json:"links,omitempty"`
}

// Score represents quality scores
type Score struct {
	Final  float64     `json:"final"`
	Detail ScoreDetail `json:"detail"`
}

// ScoreDetail represents detailed scoring
type ScoreDetail struct {
	Quality     float64 `json:"quality"`
	Popularity  float64 `json:"popularity"`
	Maintenance float64 `json:"maintenance"`
}

// Links represents package links
type Links struct {
	Npm        string `json:"npm,omitempty"`
	Homepage   string `json:"homepage,omitempty"`
	Repository string `json:"repository,omitempty"`
	Bugs       string `json:"bugs,omitempty"`
}

// ErrNotFound is returned when a package is not found
var ErrNotFound = fmt.Errorf("not found")
