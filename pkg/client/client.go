package client

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Exonical/go-npkg/pkg/auth"
	"github.com/Exonical/go-npkg/pkg/cache"
	"github.com/Exonical/go-npkg/pkg/proxy"
	"github.com/Exonical/go-npkg/pkg/types"
)

// ClientOption is a function that configures a Client
type ClientOption func(*Client)

// Client represents an NPM registry client
type Client struct {
	baseURL       string
	httpClient    *http.Client
	authenticator auth.Authenticator
	cache         *cache.Cache
	config        *types.Config
	timeout       time.Duration
}

// New creates a new NPM registry client
func New(baseURL string, opts ...ClientOption) *Client {
	// Ensure baseURL has proper format
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}

	c := &Client{
		baseURL:       baseURL,
		httpClient:    &http.Client{Timeout: 30 * time.Second},
		authenticator: &auth.NoAuth{},
		timeout:       30 * time.Second,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// WithAuth sets the authenticator for the client
func WithAuth(authenticator auth.Authenticator) ClientOption {
	return func(c *Client) {
		c.authenticator = authenticator
	}
}

// WithBasicAuth sets basic authentication
func WithBasicAuth(username, password string) ClientOption {
	return func(c *Client) {
		c.authenticator = auth.NewBasicAuth(username, password)
	}
}

// WithTokenAuth sets token authentication
func WithTokenAuth(token string) ClientOption {
	return func(c *Client) {
		c.authenticator = auth.NewTokenAuth(token)
	}
}

// WithProxy sets proxy configuration
func WithProxy(proxyConfig types.ProxyConfig) ClientOption {
	return func(c *Client) {
		transport := proxy.NewProxyTransport(proxyConfig)
		c.httpClient.Transport = transport
	}
}

// WithCache sets cache configuration
func WithCache(cacheInstance *cache.Cache) ClientOption {
	return func(c *Client) {
		c.cache = cacheInstance
	}
}

// WithTimeout sets the HTTP client timeout
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.timeout = timeout
		c.httpClient.Timeout = timeout
	}
}

// WithTLSConfig sets custom TLS configuration
func WithTLSConfig(tlsConfig *tls.Config) ClientOption {
	return func(c *Client) {
		transport := &http.Transport{TLSClientConfig: tlsConfig}
		c.httpClient.Transport = transport
	}
}

// WithConfig sets the full configuration
func WithConfig(config *types.Config) ClientOption {
	return func(c *Client) {
		c.config = config

		// Apply proxy config
		if config.Proxy.HTTPProxy != "" || config.Proxy.HTTPSProxy != "" {
			transport := proxy.NewProxyTransport(config.Proxy)
			c.httpClient.Transport = transport
		}

		// Apply auth config
		if authenticator, err := auth.NewAuthenticator(config.Auth); err == nil {
			c.authenticator = authenticator
		}
	}
}

// doRequest performs an authenticated HTTP request
func (c *Client) doRequest(req *http.Request) (*http.Response, error) {
	if err := c.authenticator.Authenticate(req); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}
	return c.httpClient.Do(req)
}

// newRequest creates a new HTTP request with common headers
func (c *Client) newRequest(method, urlStr string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, urlStr, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "npm-registry-go/1.0.0")
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// GetRegistryInfo retrieves registry information
func (c *Client) GetRegistryInfo() (*types.RegistryInfo, error) {
	req, err := c.newRequest(http.MethodGet, c.baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get registry info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned status %d", resp.StatusCode)
	}

	var info types.RegistryInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode registry info: %w", err)
	}

	return &info, nil
}

// Ping checks if the registry is accessible
func (c *Client) Ping() error {
	req, err := c.newRequest(http.MethodGet, c.baseURL+"-/ping", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to ping registry: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registry ping returned status %d", resp.StatusCode)
	}

	return nil
}

// GetPackage retrieves package metadata
func (c *Client) GetPackage(packageName string) (*types.Package, error) {
	pkgURL := c.baseURL + url.PathEscape(packageName)
	req, err := c.newRequest(http.MethodGet, pkgURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get package %s: %w", packageName, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("package %s returned status %d", packageName, resp.StatusCode)
	}

	var pkg types.Package
	if err := json.NewDecoder(resp.Body).Decode(&pkg); err != nil {
		return nil, fmt.Errorf("failed to decode package %s: %w", packageName, err)
	}

	return &pkg, nil
}

// ListPackages retrieves a list of all packages
func (c *Client) ListPackages() ([]string, error) {
	listURL := c.baseURL + "package/"
	req, err := c.newRequest(http.MethodGet, listURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list packages: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list packages returned status %d", resp.StatusCode)
	}

	var response struct {
		Packages []string `json:"packages"`
		Total    int      `json:"total"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode packages list: %w", err)
	}

	return response.Packages, nil
}

// Publish publishes a package to the registry
func (c *Client) Publish(pkg *types.Package) error {
	publishURL := c.baseURL + "package/" + pkg.Name

	data, err := json.Marshal(pkg)
	if err != nil {
		return fmt.Errorf("failed to marshal package: %w", err)
	}

	req, err := c.newRequest(http.MethodPut, publishURL, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to publish package: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("publish returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// DownloadTarball downloads a package tarball
func (c *Client) DownloadTarball(packageName, filename string) (io.ReadCloser, error) {
	tarballURL := c.baseURL + "package/" + packageName + "/-/" + filename
	req, err := c.newRequest(http.MethodGet, tarballURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download tarball: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("tarball download returned status %d", resp.StatusCode)
	}

	return resp.Body, nil
}

// SetAuth sets authentication credentials for the client
func (c *Client) SetAuth(username, password string) {
	c.authenticator = auth.NewBasicAuth(username, password)
}

// SetToken sets an authentication token for the client
func (c *Client) SetToken(token string) {
	c.authenticator = auth.NewTokenAuth(token)
}

// Search searches for packages matching the query
func (c *Client) Search(query string, size int) (*types.SearchResult, error) {
	searchURL := fmt.Sprintf("%s-/v1/search?text=%s&size=%d", c.baseURL, url.QueryEscape(query), size)

	req, err := c.newRequest(http.MethodGet, searchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create search request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to search packages: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("search returned status %d", resp.StatusCode)
	}

	var result types.SearchResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode search results: %w", err)
	}

	return &result, nil
}

// GetPackageVersion retrieves a specific version of a package
func (c *Client) GetPackageVersion(packageName, version string) (*types.Package, error) {
	pkgURL := fmt.Sprintf("%spackage/%s/%s", c.baseURL, packageName, version)

	req, err := c.newRequest(http.MethodGet, pkgURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get package %s@%s: %w", packageName, version, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("package %s@%s returned status %d", packageName, version, resp.StatusCode)
	}

	var pkg types.Package
	if err := json.NewDecoder(resp.Body).Decode(&pkg); err != nil {
		return nil, fmt.Errorf("failed to decode package %s@%s: %w", packageName, version, err)
	}

	return &pkg, nil
}

// Unpublish removes a package or version from the registry
func (c *Client) Unpublish(packageName, version string) error {
	unpublishURL := c.baseURL + "package/" + packageName
	if version != "" {
		unpublishURL += "/-rev/" + version
	}

	req, err := c.newRequest(http.MethodDelete, unpublishURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create unpublish request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to unpublish package: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unpublish returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// DownloadTarballCached downloads a tarball with caching support
func (c *Client) DownloadTarballCached(packageName, filename, integrity string) (io.ReadCloser, error) {
	cacheKey := packageName + "/" + filename

	// Try cache first
	if c.cache != nil {
		if reader, err := c.cache.Get(cacheKey); err == nil {
			return reader, nil
		}
	}

	// Download from registry
	reader, err := c.DownloadTarball(packageName, filename)
	if err != nil {
		return nil, err
	}

	// If caching is enabled, store in cache
	if c.cache != nil {
		// Read all data to cache it
		data, err := io.ReadAll(reader)
		_ = reader.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read tarball: %w", err)
		}

		// Store in cache (ignore error, caching failure is non-fatal)
		_ = c.cache.Put(cacheKey, bytes.NewReader(data), integrity)

		return io.NopCloser(bytes.NewReader(data)), nil
	}

	return reader, nil
}

// Login authenticates with the registry and returns a token
func (c *Client) Login(username, password string) (string, error) {
	loginURL := c.baseURL + "-/user/org.couchdb.user:" + username

	loginData := map[string]string{
		"name":     username,
		"password": password,
	}

	data, err := json.Marshal(loginData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal login data: %w", err)
	}

	req, err := c.newRequest(http.MethodPut, loginURL, bytes.NewBuffer(data))
	if err != nil {
		return "", fmt.Errorf("failed to create login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to login: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("login returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Token string `json:"token"`
		OK    bool   `json:"ok"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode login response: %w", err)
	}

	return result.Token, nil
}

// Logout invalidates the current authentication token
func (c *Client) Logout() error {
	logoutURL := c.baseURL + "-/user/token/" + c.getToken()

	req, err := c.newRequest(http.MethodDelete, logoutURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create logout request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to logout: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	c.authenticator = &auth.NoAuth{}
	return nil
}

func (c *Client) getToken() string {
	if tokenAuth, ok := c.authenticator.(*auth.TokenAuth); ok {
		return tokenAuth.Token
	}
	return ""
}
