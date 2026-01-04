package resolver

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Exonical/go-npkg/pkg/types"
)

// Resolver handles dependency resolution
type Resolver struct {
	fetcher PackageFetcher
}

// PackageFetcher interface for fetching package metadata
type PackageFetcher interface {
	GetPackage(name string) (*types.Package, error)
	GetPackageVersion(name, version string) (*types.Package, error)
}

// NewResolver creates a new dependency resolver
func NewResolver(fetcher PackageFetcher) *Resolver {
	return &Resolver{fetcher: fetcher}
}

// Resolve resolves all dependencies for a package
func (r *Resolver) Resolve(pkg *types.Package) (*types.DependencyTree, error) {
	visited := make(map[string]bool)
	return r.resolveDependencies(pkg.Name, pkg.Version, pkg.Dependencies, visited)
}

func (r *Resolver) resolveDependencies(name, version string, deps map[string]string, visited map[string]bool) (*types.DependencyTree, error) {
	key := name + "@" + version
	if visited[key] {
		// Circular dependency detected, return without children
		return &types.DependencyTree{
			Name:    name,
			Version: version,
		}, nil
	}
	visited[key] = true

	tree := &types.DependencyTree{
		Name:         name,
		Version:      version,
		Dependencies: make(map[string]*types.DependencyTree),
	}

	for depName, versionRange := range deps {
		// Resolve version from range
		resolvedVersion, err := r.resolveVersion(depName, versionRange)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve %s@%s: %w", depName, versionRange, err)
		}

		// Get package metadata
		depPkg, err := r.fetcher.GetPackageVersion(depName, resolvedVersion)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch %s@%s: %w", depName, resolvedVersion, err)
		}

		// Recursively resolve dependencies
		depTree, err := r.resolveDependencies(depName, resolvedVersion, depPkg.Dependencies, visited)
		if err != nil {
			return nil, err
		}

		depTree.Resolved = depPkg.Dist.Tarball
		depTree.Integrity = depPkg.Dist.Integrity

		tree.Dependencies[depName] = depTree
	}

	return tree, nil
}

// resolveVersion resolves a version range to a specific version
func (r *Resolver) resolveVersion(name, versionRange string) (string, error) {
	pkg, err := r.fetcher.GetPackage(name)
	if err != nil {
		return "", err
	}

	// Get all available versions
	versions := make([]string, 0, len(pkg.Versions))
	for v := range pkg.Versions {
		versions = append(versions, v)
	}

	// Sort versions (newest first)
	sort.Slice(versions, func(i, j int) bool {
		return compareVersions(versions[i], versions[j]) > 0
	})

	// Find matching version
	for _, v := range versions {
		if matchesRange(v, versionRange) {
			return v, nil
		}
	}

	// Check dist-tags
	if tag, ok := pkg.DistTags[versionRange]; ok {
		return tag, nil
	}

	return "", fmt.Errorf("no matching version found for %s@%s", name, versionRange)
}

// matchesRange checks if a version matches a version range
func matchesRange(version, versionRange string) bool {
	// Handle exact version
	if version == versionRange {
		return true
	}

	// Handle "latest" tag
	if versionRange == "latest" || versionRange == "*" {
		return true
	}

	// Handle caret (^) - compatible with version
	if strings.HasPrefix(versionRange, "^") {
		baseVersion := strings.TrimPrefix(versionRange, "^")
		return isCompatible(version, baseVersion)
	}

	// Handle tilde (~) - approximately equivalent
	if strings.HasPrefix(versionRange, "~") {
		baseVersion := strings.TrimPrefix(versionRange, "~")
		return isApproximatelyEqual(version, baseVersion)
	}

	// Handle >= operator
	if strings.HasPrefix(versionRange, ">=") {
		baseVersion := strings.TrimPrefix(versionRange, ">=")
		return compareVersions(version, baseVersion) >= 0
	}

	// Handle > operator
	if strings.HasPrefix(versionRange, ">") {
		baseVersion := strings.TrimPrefix(versionRange, ">")
		return compareVersions(version, baseVersion) > 0
	}

	// Handle <= operator
	if strings.HasPrefix(versionRange, "<=") {
		baseVersion := strings.TrimPrefix(versionRange, "<=")
		return compareVersions(version, baseVersion) <= 0
	}

	// Handle < operator
	if strings.HasPrefix(versionRange, "<") {
		baseVersion := strings.TrimPrefix(versionRange, "<")
		return compareVersions(version, baseVersion) < 0
	}

	return false
}

// isCompatible checks if version is compatible with base (caret range)
func isCompatible(version, base string) bool {
	vParts := parseVersion(version)
	bParts := parseVersion(base)

	// Major version must match
	if vParts[0] != bParts[0] {
		return false
	}

	// If major is 0, minor must also match
	if vParts[0] == 0 && vParts[1] != bParts[1] {
		return false
	}

	return compareVersions(version, base) >= 0
}

// isApproximatelyEqual checks if version is approximately equal (tilde range)
func isApproximatelyEqual(version, base string) bool {
	vParts := parseVersion(version)
	bParts := parseVersion(base)

	// Major and minor must match
	if vParts[0] != bParts[0] || vParts[1] != bParts[1] {
		return false
	}

	return compareVersions(version, base) >= 0
}

// parseVersion parses a semver string into parts
func parseVersion(version string) [3]int {
	parts := [3]int{0, 0, 0}

	// Remove any prerelease or build metadata
	version = strings.Split(version, "-")[0]
	version = strings.Split(version, "+")[0]

	segments := strings.Split(version, ".")
	for i := 0; i < len(segments) && i < 3; i++ {
		_, _ = fmt.Sscanf(segments[i], "%d", &parts[i])
	}

	return parts
}

// compareVersions compares two semver versions
// Returns: -1 if a < b, 0 if a == b, 1 if a > b
func compareVersions(a, b string) int {
	aParts := parseVersion(a)
	bParts := parseVersion(b)

	for i := 0; i < 3; i++ {
		if aParts[i] < bParts[i] {
			return -1
		}
		if aParts[i] > bParts[i] {
			return 1
		}
	}

	return 0
}

// GenerateLockFile generates a lock file from a dependency tree
func GenerateLockFile(name, version string, tree *types.DependencyTree) *types.LockFile {
	lockFile := &types.LockFile{
		Name:            name,
		Version:         version,
		LockfileVersion: 3,
		Packages:        make(map[string]types.LockedPackage),
	}

	flattenTree(tree, lockFile.Packages, "")
	return lockFile
}

func flattenTree(tree *types.DependencyTree, packages map[string]types.LockedPackage, prefix string) {
	var path string
	if prefix != "" {
		path = prefix + "/node_modules/" + tree.Name
	} else {
		path = "node_modules/" + tree.Name
	}

	deps := make(map[string]string)
	for name, dep := range tree.Dependencies {
		deps[name] = dep.Version
	}

	packages[path] = types.LockedPackage{
		Version:      tree.Version,
		Resolved:     tree.Resolved,
		Integrity:    tree.Integrity,
		Dependencies: deps,
	}

	for _, dep := range tree.Dependencies {
		flattenTree(dep, packages, path)
	}
}
