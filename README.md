# NPM Registry

A Go library for building npm-compatible package registries. Designed to be embedded in other applications.

## Features

- **Embeddable library**: Import and use in your Go applications
- **npm/yarn/pnpm compatible**: Full npm registry protocol support
- **Hybrid registry**: Serve private packages + proxy to upstream (like Verdaccio)
- **Pluggable storage**: Implement custom backends (filesystem, S3, database)
- **Semantic versioning**: Full npm-compatible semver range support

## Installation

```bash
go get github.com/Exonical/go-npkg
```

## Library Usage

### Embed a Registry Server

```go
package main

import (
    "net/http"
    "log"

    npmregistry "github.com/Exonical/go-npkg"
)

func main() {
    // Create a hybrid registry (local + upstream proxy)
    registry, err := npmregistry.NewRegistry(
        npmregistry.WithStorage("./packages"),
        npmregistry.WithBaseURL("http://localhost:4873"),
        npmregistry.WithUplink(npmregistry.Npmjs()),
        npmregistry.WithTarballCaching(true),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Use as http.Handler - integrate with your router
    http.Handle("/", registry)
    log.Fatal(http.ListenAndServe(":4873", nil))
}
```

### Fetch Packages Programmatically

```go
package main

import (
    "fmt"
    npmregistry "github.com/Exonical/go-npkg"
)

func main() {
    // Create client for any npm registry
    client := npmregistry.NewClient("https://registry.npmjs.org")

    // Fetch package metadata
    pkg, err := client.GetPackage("lodash")
    if err != nil {
        panic(err)
    }
    fmt.Printf("Latest: %s\n", pkg.DistTags["latest"])

    // Download tarball
    tarball, err := client.DownloadTarball("lodash", "lodash-4.17.21.tgz")
    if err != nil {
        panic(err)
    }
    defer tarball.Close()
}
```

### Use Uplink Directly (Proxy to npmjs)

```go
package main

import (
    "fmt"
    npmregistry "github.com/Exonical/go-npkg"
)

func main() {
    // Create uplink to npmjs
    uplink := npmregistry.Npmjs()

    // Fetch full packument (all versions)
    packument, err := uplink.GetPackument("express")
    if err != nil {
        panic(err)
    }

    fmt.Printf("Package: %s\n", packument.Name)
    fmt.Printf("Versions: %d\n", len(packument.Versions))
    fmt.Printf("Latest: %s\n", packument.DistTags["latest"])
}
```

### Semver Resolution

```go
package main

import (
    "fmt"
    npmregistry "github.com/Exonical/go-npkg"
)

func main() {
    versions := []string{"1.0.0", "1.2.3", "1.5.0", "2.0.0"}

    // Find best match for ^1.0.0
    best, _ := npmregistry.MaxSatisfying(versions, "^1.0.0")
    fmt.Println(best) // "1.5.0"

    // Parse and check ranges
    r, _ := npmregistry.ParseRange(">=1.2.0 <2.0.0")
    v, _ := npmregistry.ParseVersion("1.5.0")
    fmt.Println(r.Satisfies(v)) // true
}
```

### Custom Storage Backend

```go
package main

import (
    "io"
    npmregistry "github.com/Exonical/go-npkg"
)

// Implement PackageStore for custom metadata storage
type MyStore struct{}

func (s *MyStore) GetPackument(name string) (*npmregistry.Packument, error) {
    // Fetch from database, S3, etc.
    return nil, nil
}

func (s *MyStore) SavePackument(pkg *npmregistry.Packument) error {
    // Save to database, S3, etc.
    return nil
}

func (s *MyStore) DeletePackument(name string) error {
    return nil
}

func (s *MyStore) ListPackages() ([]string, error) {
    return nil, nil
}

// Implement BlobStore for custom tarball storage
func (s *MyStore) GetTarball(name, filename string) (io.ReadCloser, error) {
    return nil, nil
}

func (s *MyStore) SaveTarball(name, filename string, data io.Reader) error {
    return nil
}

func (s *MyStore) HasTarball(name, filename string) bool {
    return false
}
```

## Standalone Server (Optional)

The library includes an example server that can be run standalone:

```bash
go run examples/server/main.go -port 4873 -storage ./packages
```

Then configure npm:

```bash
npm set registry http://localhost:4873
npm install lodash  # Proxied from npmjs.org and cached
```

### Client with Authentication

```go
package main

import (
    "time"
    "github.com/Exonical/go-npkg/pkg/client"
    "github.com/Exonical/go-npkg/pkg/types"
)

func main() {
    // Basic client
    npmClient := client.New("http://localhost:8080")

    // Client with token auth
    npmClient := client.New("http://localhost:8080",
        client.WithTokenAuth("your-token-here"),
    )

    // Client with basic auth
    npmClient := client.New("http://localhost:8080",
        client.WithBasicAuth("username", "password"),
    )

    // Client with proxy
    npmClient := client.New("http://localhost:8080",
        client.WithProxy(types.ProxyConfig{
            HTTPProxy:  "http://proxy:8080",
            HTTPSProxy: "https://proxy:8443",
            NoProxy:    []string{"localhost", "*.internal"},
        }),
    )

    // Client with timeout
    npmClient := client.New("http://localhost:8080",
        client.WithTimeout(60 * time.Second),
    )

    // Login and get token
    token, err := npmClient.Login("username", "password")
    if err != nil {
        panic(err)
    }
    npmClient.SetToken(token)
}
```

### Using Cache

```go
package main

import (
    "time"
    "github.com/Exonical/go-npkg/pkg/cache"
    "github.com/Exonical/go-npkg/pkg/client"
    "github.com/Exonical/go-npkg/pkg/types"
)

func main() {
    // Create cache
    pkgCache, _ := cache.NewCache(types.CacheConfig{
        Enabled:   true,
        Directory: "/tmp/npm-cache",
        TTL:       24 * time.Hour,
        MaxSize:   1024 * 1024 * 1024, // 1GB
    })

    // Client with cache
    npmClient := client.New("http://localhost:8080",
        client.WithCache(pkgCache),
    )

    // Download with caching
    reader, _ := npmClient.DownloadTarballCached("lodash", "lodash-4.17.21.tgz", "sha512-...")
}
```

### Configuration File

```go
package main

import (
    "github.com/Exonical/go-npkg/pkg/client"
    "github.com/Exonical/go-npkg/pkg/config"
)

func main() {
    // Load config from home directory
    cfg, _ := config.LoadFromHome()

    // Or load from specific path
    cfg, _ := config.Load("/path/to/.npmregistry.json")

    // Create client with config
    npmClient := client.New(cfg.Registries[0].URL,
        client.WithConfig(cfg),
    )
}
```

### Dependency Resolution

```go
package main

import (
    "github.com/Exonical/go-npkg/pkg/client"
    "github.com/Exonical/go-npkg/pkg/resolver"
)

func main() {
    npmClient := client.New("http://localhost:8080")

    // Create resolver
    res := resolver.NewResolver(npmClient)

    // Resolve dependencies
    pkg, _ := npmClient.GetPackage("my-package")
    tree, _ := res.Resolve(pkg)

    // Generate lock file
    lockFile := resolver.GenerateLockFile(pkg.Name, pkg.Version, tree)
}
```

## API Endpoints (npm-compatible)

### Registry
- `GET /` - Registry info (CouchDB-style)
- `GET /-/ping` - Health check
- `GET /-/whoami` - Current user

### Packages (standard npm protocol)
- `GET /:package` - Get full packument (all versions)
- `GET /:package/:version` - Get specific version
- `GET /@scope%2Fname` - Scoped package metadata
- `PUT /:package` - Publish package (npm publish format)
- `DELETE /:package` - Unpublish package
- `GET /:package/-/:filename.tgz` - Download tarball

### Search
- `GET /-/v1/search?text=query&size=20` - Search packages

### Authentication
- `PUT /-/user/org.couchdb.user:username` - Login/Register
- `DELETE /-/user/token/:token` - Logout

## Configuration File Format

```json
{
  "registries": [
    {
      "name": "private",
      "url": "https://npm.mycompany.com",
      "auth": {
        "type": "token",
        "token": "your-token"
      },
      "priority": 0,
      "scopes": ["@mycompany"]
    },
    {
      "name": "npmjs",
      "url": "https://registry.npmjs.org",
      "priority": 1
    }
  ],
  "defaultRegistry": "npmjs",
  "cache": {
    "enabled": true,
    "directory": "~/.npm-cache",
    "ttl": "24h",
    "maxSize": 1073741824
  },
  "proxy": {
    "httpProxy": "http://proxy:8080",
    "httpsProxy": "https://proxy:8443",
    "noProxy": ["localhost", "*.internal"]
  }
}
```

## Package Structure

```
pkg/
├── auth/        # Authentication (basic, token, certificate)
├── cache/       # Package caching
├── client/      # NPM registry client
├── config/      # Configuration management
├── integrity/   # Package integrity verification (SHA-1, SHA-256, SHA-512)
├── proxy/       # HTTP proxy support
├── resolver/    # Dependency resolution
├── semver/      # Semantic versioning (^, ~, ranges, prerelease)
├── server/      # NPM registry server (hybrid + npm-compatible)
├── storage/     # Filesystem storage for packages/tarballs
├── types/       # Shared types and models
└── uplink/      # Upstream registry proxy (npmjs, etc.)
```

## Semver Support

Full npm-compatible semantic versioning:

```go
import "github.com/Exonical/go-npkg/pkg/semver"

// Parse versions
v, _ := semver.Parse("1.2.3-beta.1")

// Compare versions
v1.GreaterThan(v2)
v1.LessThan(v2)

// Parse and match ranges
r, _ := semver.ParseRange("^1.2.0")
r.Satisfies(v) // true if v matches ^1.2.0

// Find best matching version
best, _ := semver.MaxSatisfying([]string{"1.0.0", "1.2.3", "2.0.0"}, "^1.0.0")
// Returns "1.2.3"
```

Supported range formats:
- Exact: `1.2.3`
- Caret: `^1.2.3` (compatible with 1.x.x)
- Tilde: `~1.2.3` (compatible with 1.2.x)
- Comparisons: `>=1.0.0`, `<2.0.0`, `>1.0.0`, `<=2.0.0`
- X-ranges: `1.x`, `1.2.x`
- Hyphen: `1.0.0 - 2.0.0`
- Wildcards: `*`, `latest`

## License

MIT
