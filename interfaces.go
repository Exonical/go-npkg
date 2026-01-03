package npmregistry

import (
	"io"
	"net/http"

	"github.com/Exonical/go-npkg/uplink"
)

// PackageStore defines the interface for package metadata storage.
// Implement this interface to create custom storage backends.
type PackageStore interface {
	// GetPackument retrieves the full package document (all versions).
	GetPackument(name string) (*uplink.Packument, error)

	// SavePackument stores a package document.
	SavePackument(packument *uplink.Packument) error

	// DeletePackument removes a package and all its versions.
	DeletePackument(name string) error

	// ListPackages returns all stored package names.
	ListPackages() ([]string, error)
}

// BlobStore defines the interface for tarball storage.
// Implement this interface to create custom blob storage backends (e.g., S3, GCS).
type BlobStore interface {
	// GetTarball retrieves a tarball by package name and filename.
	GetTarball(name, filename string) (io.ReadCloser, error)

	// SaveTarball stores a tarball.
	SaveTarball(name, filename string, data io.Reader) error

	// HasTarball checks if a tarball exists.
	HasTarball(name, filename string) bool
}

// Authenticator defines the interface for request authentication.
// Implement this interface to create custom authentication providers.
type Authenticator interface {
	// Authenticate adds authentication to an HTTP request.
	Authenticate(req *http.Request) error
}

// PackageFetcher defines the interface for fetching package metadata.
// Both Client and Uplink implement this interface.
type PackageFetcher interface {
	// GetPackument fetches the full package document.
	GetPackument(name string) (*uplink.Packument, error)

	// GetVersion fetches a specific version.
	GetVersion(name, version string) (*uplink.Version, error)
}

// TarballFetcher defines the interface for fetching tarballs.
type TarballFetcher interface {
	// GetTarball fetches a tarball and returns the body and content type.
	GetTarball(tarballURL string) (io.ReadCloser, string, error)
}

// VersionMatcher defines the interface for version resolution.
type VersionMatcher interface {
	// Satisfies checks if a version satisfies the constraint.
	Satisfies(version *SemverVersion) bool
}

// Ensure our types implement the interfaces
var (
	_ PackageStore = (*Storage)(nil)
	_ BlobStore    = (*Storage)(nil)
)
