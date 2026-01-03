package proxy

import (
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/Exonical/go-npkg/types"
)

// ProxyTransport wraps http.Transport with proxy support
type ProxyTransport struct {
	*http.Transport
	config types.ProxyConfig
}

// NewProxyTransport creates a new transport with proxy configuration
func NewProxyTransport(config types.ProxyConfig) *ProxyTransport {
	transport := &http.Transport{}

	if config.HTTPProxy != "" || config.HTTPSProxy != "" {
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			// Check if host is in NoProxy list
			for _, noProxy := range config.NoProxy {
				if matchNoProxy(req.URL.Host, noProxy) {
					return nil, nil
				}
			}

			// Use appropriate proxy based on scheme
			var proxyURL string
			if req.URL.Scheme == "https" && config.HTTPSProxy != "" {
				proxyURL = config.HTTPSProxy
			} else if config.HTTPProxy != "" {
				proxyURL = config.HTTPProxy
			}

			if proxyURL == "" {
				return nil, nil
			}

			return url.Parse(proxyURL)
		}
	}

	return &ProxyTransport{
		Transport: transport,
		config:    config,
	}
}

// matchNoProxy checks if a host matches a no-proxy pattern
func matchNoProxy(host, pattern string) bool {
	// Exact match
	if host == pattern {
		return true
	}

	// Wildcard match (e.g., *.example.com)
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // Remove the *
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}

	// Domain suffix match (e.g., .example.com matches sub.example.com)
	if strings.HasPrefix(pattern, ".") {
		if strings.HasSuffix(host, pattern) {
			return true
		}
	}

	return false
}

// ConfigFromEnv creates proxy config from environment variables
func ConfigFromEnv() types.ProxyConfig {
	return types.ProxyConfig{
		HTTPProxy:  getEnvAny("HTTP_PROXY", "http_proxy"),
		HTTPSProxy: getEnvAny("HTTPS_PROXY", "https_proxy"),
		NoProxy:    parseNoProxy(getEnvAny("NO_PROXY", "no_proxy")),
	}
}

func getEnvAny(keys ...string) string {
	for _, key := range keys {
		if val := getEnv(key); val != "" {
			return val
		}
	}
	return ""
}

func getEnv(key string) string {
	// This would normally use os.Getenv, but we'll keep it simple
	// In production, you'd import "os" and use os.Getenv(key)
	return os.Getenv(key)
}

func parseNoProxy(noProxy string) []string {
	if noProxy == "" {
		return nil
	}

	parts := strings.Split(noProxy, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
