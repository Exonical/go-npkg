package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Exonical/go-npkg/types"
)

// Cache provides package caching functionality
type Cache struct {
	config    types.CacheConfig
	mu        sync.RWMutex
	index     map[string]*CacheEntry
	indexPath string
}

// CacheEntry represents a cached item
type CacheEntry struct {
	Key       string    `json:"key"`
	Path      string    `json:"path"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Integrity string    `json:"integrity"`
}

// NewCache creates a new cache instance
func NewCache(config types.CacheConfig) (*Cache, error) {
	if !config.Enabled {
		return &Cache{config: config}, nil
	}

	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(config.Directory, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	cache := &Cache{
		config:    config,
		index:     make(map[string]*CacheEntry),
		indexPath: filepath.Join(config.Directory, "index.json"),
	}

	// Load existing index
	if err := cache.loadIndex(); err != nil {
		// Index doesn't exist or is corrupted, start fresh
		cache.index = make(map[string]*CacheEntry)
	}

	return cache, nil
}

// Get retrieves an item from cache
func (c *Cache) Get(key string) (io.ReadCloser, error) {
	if !c.config.Enabled {
		return nil, fmt.Errorf("cache is disabled")
	}

	c.mu.RLock()
	entry, exists := c.index[key]
	c.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("cache miss: %s", key)
	}

	// Check expiration
	if time.Now().After(entry.ExpiresAt) {
		_ = c.Delete(key)
		return nil, fmt.Errorf("cache expired: %s", key)
	}

	file, err := os.Open(entry.Path)
	if err != nil {
		_ = c.Delete(key)
		return nil, fmt.Errorf("failed to open cached file: %w", err)
	}

	return file, nil
}

// Put stores an item in cache
func (c *Cache) Put(key string, data io.Reader, integrity string) error {
	if !c.config.Enabled {
		return nil
	}

	// Generate file path
	hash := sha256.Sum256([]byte(key))
	filename := hex.EncodeToString(hash[:])
	filePath := filepath.Join(c.config.Directory, filename)

	// Write data to file
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create cache file: %w", err)
	}
	defer func() { _ = file.Close() }()

	size, err := io.Copy(file, data)
	if err != nil {
		_ = os.Remove(filePath)
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	// Create cache entry
	entry := &CacheEntry{
		Key:       key,
		Path:      filePath,
		Size:      size,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(c.config.TTL),
		Integrity: integrity,
	}

	c.mu.Lock()
	c.index[key] = entry
	c.mu.Unlock()

	return c.saveIndex()
}

// Delete removes an item from cache
func (c *Cache) Delete(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.index[key]
	if !exists {
		return nil
	}

	// Remove file
	_ = os.Remove(entry.Path)

	// Remove from index
	delete(c.index, key)

	return c.saveIndex()
}

// Clear removes all items from cache
func (c *Cache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, entry := range c.index {
		_ = os.Remove(entry.Path)
	}

	c.index = make(map[string]*CacheEntry)
	return c.saveIndex()
}

// Prune removes expired entries
func (c *Cache) Prune() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.index {
		if now.After(entry.ExpiresAt) {
			_ = os.Remove(entry.Path)
			delete(c.index, key)
		}
	}

	return c.saveIndex()
}

// Size returns the total size of cached items
func (c *Cache) Size() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var total int64
	for _, entry := range c.index {
		total += entry.Size
	}
	return total
}

// loadIndex loads the cache index from disk
func (c *Cache) loadIndex() error {
	data, err := os.ReadFile(c.indexPath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &c.index)
}

// saveIndex saves the cache index to disk
func (c *Cache) saveIndex() error {
	data, err := json.MarshalIndent(c.index, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(c.indexPath, data, 0644)
}
