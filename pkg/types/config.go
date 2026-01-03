package types

import (
	"time"
)

// Config represents the NPM registry client configuration
type Config struct {
	Registries      []RegistryConfig `json:"registries" yaml:"registries"`
	DefaultRegistry string           `json:"defaultRegistry" yaml:"defaultRegistry"`
	Cache           CacheConfig      `json:"cache" yaml:"cache"`
	Proxy           ProxyConfig      `json:"proxy" yaml:"proxy"`
	Auth            AuthConfig       `json:"auth" yaml:"auth"`
}

// RegistryConfig represents a single registry configuration
type RegistryConfig struct {
	Name     string     `json:"name" yaml:"name"`
	URL      string     `json:"url" yaml:"url"`
	Auth     AuthConfig `json:"auth" yaml:"auth"`
	Priority int        `json:"priority" yaml:"priority"`
	Scopes   []string   `json:"scopes" yaml:"scopes"`
}

// CacheConfig represents cache configuration
type CacheConfig struct {
	Enabled   bool          `json:"enabled" yaml:"enabled"`
	Directory string        `json:"directory" yaml:"directory"`
	TTL       time.Duration `json:"ttl" yaml:"ttl"`
	MaxSize   int64         `json:"maxSize" yaml:"maxSize"`
}

// ProxyConfig represents proxy configuration
type ProxyConfig struct {
	HTTPProxy  string   `json:"httpProxy" yaml:"httpProxy"`
	HTTPSProxy string   `json:"httpsProxy" yaml:"httpsProxy"`
	NoProxy    []string `json:"noProxy" yaml:"noProxy"`
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	Type        AuthType `json:"type" yaml:"type"`
	Token       string   `json:"token,omitempty" yaml:"token,omitempty"`
	Username    string   `json:"username,omitempty" yaml:"username,omitempty"`
	Password    string   `json:"password,omitempty" yaml:"password,omitempty"`
	Certificate string   `json:"certificate,omitempty" yaml:"certificate,omitempty"`
	Key         string   `json:"key,omitempty" yaml:"key,omitempty"`
}

// AuthType represents the type of authentication
type AuthType string

const (
	AuthTypeNone  AuthType = "none"
	AuthTypeBasic AuthType = "basic"
	AuthTypeToken AuthType = "token"
	AuthTypeCert  AuthType = "certificate"
)

// SearchResult represents a package search result
type SearchResult struct {
	Objects []SearchObject `json:"objects"`
	Total   int            `json:"total"`
	Time    string         `json:"time"`
}

// SearchObject represents a single search result object
type SearchObject struct {
	Package     SearchPackage `json:"package"`
	Score       Score         `json:"score"`
	SearchScore float64       `json:"searchScore"`
}

// SearchPackage represents package info in search results
type SearchPackage struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Keywords    []string `json:"keywords"`
	Author      *Person  `json:"author"`
	Publisher   *Person  `json:"publisher"`
	Date        string   `json:"date"`
	Links       Links    `json:"links"`
}

// Score represents package quality scores
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
	NPM        string `json:"npm"`
	Homepage   string `json:"homepage"`
	Repository string `json:"repository"`
	Bugs       string `json:"bugs"`
}

// DependencyTree represents resolved dependencies
type DependencyTree struct {
	Name         string                     `json:"name"`
	Version      string                     `json:"version"`
	Dependencies map[string]*DependencyTree `json:"dependencies,omitempty"`
	Resolved     string                     `json:"resolved"`
	Integrity    string                     `json:"integrity"`
}

// LockFile represents a package lock file
type LockFile struct {
	Name            string                   `json:"name"`
	Version         string                   `json:"version"`
	LockfileVersion int                      `json:"lockfileVersion"`
	Packages        map[string]LockedPackage `json:"packages"`
}

// LockedPackage represents a locked package entry
type LockedPackage struct {
	Version      string            `json:"version"`
	Resolved     string            `json:"resolved"`
	Integrity    string            `json:"integrity"`
	Dependencies map[string]string `json:"dependencies,omitempty"`
}
