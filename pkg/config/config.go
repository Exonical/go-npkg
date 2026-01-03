package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Exonical/go-npkg/types"
)

const (
	DefaultConfigFile = ".npmregistry.json"
	DefaultCacheDir   = ".npm-cache"
)

// Load loads configuration from file
func Load(path string) (*types.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config types.Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// Save saves configuration to file
func Save(config *types.Config, path string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// DefaultConfig returns the default configuration
func DefaultConfig() *types.Config {
	homeDir, _ := os.UserHomeDir()
	cacheDir := filepath.Join(homeDir, DefaultCacheDir)

	return &types.Config{
		Registries: []types.RegistryConfig{
			{
				Name:     "npmjs",
				URL:      "https://registry.npmjs.org",
				Priority: 0,
			},
		},
		DefaultRegistry: "npmjs",
		Cache: types.CacheConfig{
			Enabled:   true,
			Directory: cacheDir,
			TTL:       24 * time.Hour,
			MaxSize:   1024 * 1024 * 1024, // 1GB
		},
		Proxy: types.ProxyConfig{},
		Auth:  types.AuthConfig{Type: types.AuthTypeNone},
	}
}

// LoadFromHome loads configuration from user's home directory
func LoadFromHome() (*types.Config, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return DefaultConfig(), nil
	}

	configPath := filepath.Join(homeDir, DefaultConfigFile)
	return Load(configPath)
}

// SaveToHome saves configuration to user's home directory
func SaveToHome(config *types.Config) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	configPath := filepath.Join(homeDir, DefaultConfigFile)
	return Save(config, configPath)
}

// AddRegistry adds a new registry to the configuration
func AddRegistry(config *types.Config, registry types.RegistryConfig) error {
	// Check for duplicate names
	for _, r := range config.Registries {
		if r.Name == registry.Name {
			return fmt.Errorf("registry %s already exists", registry.Name)
		}
	}

	config.Registries = append(config.Registries, registry)
	return nil
}

// RemoveRegistry removes a registry from the configuration
func RemoveRegistry(config *types.Config, name string) error {
	for i, r := range config.Registries {
		if r.Name == name {
			config.Registries = append(config.Registries[:i], config.Registries[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("registry %s not found", name)
}

// GetRegistry retrieves a registry by name
func GetRegistry(config *types.Config, name string) (*types.RegistryConfig, error) {
	for _, r := range config.Registries {
		if r.Name == name {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("registry %s not found", name)
}

// GetRegistryForScope finds the appropriate registry for a scoped package
func GetRegistryForScope(config *types.Config, scope string) *types.RegistryConfig {
	for _, r := range config.Registries {
		for _, s := range r.Scopes {
			if s == scope {
				return &r
			}
		}
	}

	// Return default registry
	for _, r := range config.Registries {
		if r.Name == config.DefaultRegistry {
			return &r
		}
	}

	// Return first registry if no default
	if len(config.Registries) > 0 {
		return &config.Registries[0]
	}

	return nil
}
