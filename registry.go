// Package npmregistry provides a Go library for building npm-compatible package registries.
//
// This library can be used to:
//   - Create a private npm registry server
//   - Build a caching proxy for npmjs.org
//   - Implement custom package storage backends
//   - Integrate npm package management into Go applications
//
// # Quick Start
//
// Create a hybrid registry that serves local packages and proxies to npmjs:
//
//	import "github.com/Exonical/go-npkg
//
//	// Create registry with default options
//	reg, err := npmregistry.NewRegistry(
//	    npmregistry.WithStorage("./packages"),
//	    npmregistry.WithUplink(npmregistry.Npmjs()),
//	)
//
//	// Use as http.Handler
//	http.ListenAndServe(":4873", reg)
//
// # Client Usage
//
// Fetch packages programmatically:
//
//	client := npmregistry.NewClient("https://registry.npmjs.org")
//	pkg, err := client.GetPackage("lodash")
//	tarball, err := client.GetTarball("lodash", "4.17.21")
//
// # Storage Backends
//
// Implement custom storage by satisfying the Storage interface:
//
//	type Storage interface {
//	    GetPackage(name string) (*Package, error)
//	    PutPackage(pkg *Package) error
//	    GetTarball(name, version string) (io.ReadCloser, error)
//	    PutTarball(name, version string, data io.Reader) error
//	}
package npmregistry

import (
	"github.com/Exonical/go-npkg/pkg/client"
	"github.com/Exonical/go-npkg/pkg/semver"
	"github.com/Exonical/go-npkg/pkg/server"
	"github.com/Exonical/go-npkg/pkg/storage"
	"github.com/Exonical/go-npkg/pkg/uplink"
)

// Re-export core types for convenience
type (
	// Registry is an npm-compatible registry server that can be used as http.Handler.
	Registry = server.HybridRegistry

	// RegistryConfig holds configuration for creating a Registry.
	RegistryConfig = server.HybridConfig

	// Client is an npm registry client for fetching packages and tarballs.
	Client = client.Client

	// ClientOption configures a Client.
	ClientOption = client.ClientOption

	// Storage provides persistent storage for packages and tarballs.
	Storage = storage.Storage

	// Uplink represents an upstream npm registry (e.g., npmjs.org).
	Uplink = uplink.Uplink

	// UplinkConfig holds configuration for an Uplink.
	UplinkConfig = uplink.Config

	// Packument is the full npm package document containing all versions.
	Packument = uplink.Packument

	// Version represents a single package version.
	Version = uplink.Version

	// Dist contains distribution info (tarball URL, integrity).
	Dist = uplink.Dist

	// SearchResult contains npm search results.
	SearchResult = uplink.SearchResult

	// SemverVersion is a parsed semantic version.
	SemverVersion = semver.Version

	// SemverRange is a parsed version range constraint.
	SemverRange = semver.Range

	// PackageRule defines access rules for packages matching a pattern.
	PackageRule = server.PackageRule
)

// NewRegistry creates a new npm-compatible registry.
// The registry can be used as an http.Handler or started with Start().
//
// Example:
//
//	reg, err := npmregistry.NewRegistry(
//	    npmregistry.WithStorage("./packages"),
//	    npmregistry.WithBaseURL("http://localhost:4873"),
//	    npmregistry.WithUplink(npmregistry.Npmjs()),
//	    npmregistry.WithTarballCaching(true),
//	)
//	http.ListenAndServe(":4873", reg)
func NewRegistry(opts ...RegistryOption) (*Registry, error) {
	config := RegistryConfig{
		StorageDir: "./storage",
		BaseURL:    "http://localhost:4873",
	}

	for _, opt := range opts {
		opt(&config)
	}

	return server.NewHybridRegistry(config)
}

// RegistryOption configures a Registry.
type RegistryOption func(*RegistryConfig)

// WithStorage sets the storage directory for packages and tarballs.
func WithStorage(dir string) RegistryOption {
	return func(c *RegistryConfig) {
		c.StorageDir = dir
	}
}

// WithBaseURL sets the base URL for the registry.
// This is used when rewriting tarball URLs in package metadata.
func WithBaseURL(url string) RegistryOption {
	return func(c *RegistryConfig) {
		c.BaseURL = url
	}
}

// WithUplinks sets the upstream registries to proxy to.
// Each uplink can have its own caching and auth settings.
func WithUplinks(uplinks ...*Uplink) RegistryOption {
	return func(c *RegistryConfig) {
		c.Uplinks = uplinks
	}
}

// WithPackageRules package access rules.
// Rules are matched in order; first match wins.
func WithPackageRules(rules ...PackageRule) RegistryOption {
	return func(c *RegistryConfig) {
		c.PackageRules = rules
	}
}

// WithUplink is a marker option for adding uplinks.
// Note: Uplinks are added after registry creation via registry.AddUplink().
// The default registry already includes npmjs.org as an uplink.
func WithUplink(u *Uplink) RegistryOption {
	// This is handled post-creation; the option is for API consistency
	return func(c *RegistryConfig) {}
}

// NewClient creates a new npm registry client.
//
// Example:
//
//	// Basic client
//	client := npmregistry.NewClient("https://registry.npmjs.org")
//
//	// With authentication
//	client := npmregistry.NewClient("https://registry.npmjs.org",
//	    npmregistry.WithToken("your-token"),
//	)
func NewClient(registryURL string, opts ...ClientOption) *Client {
	return client.New(registryURL, opts...)
}

// WithToken sets bearer token authentication for the client.
func WithToken(token string) ClientOption {
	return client.WithTokenAuth(token)
}

// WithBasicAuth sets basic authentication for the client.
func WithBasicAuth(username, password string) ClientOption {
	return client.WithBasicAuth(username, password)
}

// NewStorage creates a new filesystem storage backend.
//
// Example:
//
//	store, err := npmregistry.NewStorage("./packages")
//	pkg, err := store.GetPackument("lodash")
func NewStorage(dir string) (*Storage, error) {
	return storage.New(dir)
}

// NewUplink creates a new upstream registry client.
//
// Example:
//
//	// Custom uplink
//	up := npmregistry.NewUplink(npmregistry.UplinkConfig{
//	    Name: "github",
//	    URL:  "https://npm.pkg.github.com",
//	})
func NewUplink(config UplinkConfig) *Uplink {
	return uplink.New(config)
}

// Npmjs returns an uplink configured for the official npm registry.
//
// Example:
//
//	up := npmregistry.Npmjs()
//	pkg, err := up.GetPackument("lodash")
func Npmjs() *Uplink {
	return uplink.NewNpmjs()
}

// ParseVersion parses a semantic version string.
//
// Example:
//
//	v, err := npmregistry.ParseVersion("1.2.3-beta.1")
//	fmt.Println(v.Major, v.Minor, v.Patch) // 1 2 3
func ParseVersion(version string) (*SemverVersion, error) {
	return semver.Parse(version)
}

// ParseRange parses a version range string (npm-compatible).
//
// Supported formats:
//   - Exact: "1.2.3"
//   - Caret: "^1.2.3"
//   - Tilde: "~1.2.3"
//   - Comparisons: ">=1.0.0", "<2.0.0"
//   - X-ranges: "1.x", "1.2.x"
//   - Hyphen: "1.0.0 - 2.0.0"
//
// Example:
//
//	r, err := npmregistry.ParseRange("^1.2.0")
//	v, _ := npmregistry.ParseVersion("1.5.0")
//	fmt.Println(r.Satisfies(v)) // true
func ParseRange(rangeStr string) (*SemverRange, error) {
	return semver.ParseRange(rangeStr)
}

// MaxSatisfying returns the highest version that satisfies the range.
//
// Example:
//
//	versions := []string{"1.0.0", "1.2.3", "2.0.0"}
//	best, err := npmregistry.MaxSatisfying(versions, "^1.0.0")
//	fmt.Println(best) // "1.2.3"
func MaxSatisfying(versions []string, rangeStr string) (string, error) {
	return semver.MaxSatisfying(versions, rangeStr)
}

// SortVersions sorts version strings in descending order (newest first).
func SortVersions(versions []string) []string {
	return semver.SortVersions(versions)
}
