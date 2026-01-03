package types

import (
	"time"
)

// Package represents an NPM package metadata
type Package struct {
	ID               string               `json:"_id"`
	Name             string               `json:"name"`
	Version          string               `json:"version"`
	Description      string               `json:"description,omitempty"`
	Author           *Person              `json:"author,omitempty"`
	Maintainers      []Person             `json:"maintainers,omitempty"`
	Keywords         []string             `json:"keywords,omitempty"`
	License          string               `json:"license,omitempty"`
	Homepage         string               `json:"homepage,omitempty"`
	Repository       *Repository          `json:"repository,omitempty"`
	Bugs             *Bugs                `json:"bugs,omitempty"`
	Dependencies     map[string]string    `json:"dependencies,omitempty"`
	DevDependencies  map[string]string    `json:"devDependencies,omitempty"`
	PeerDependencies map[string]string    `json:"peerDependencies,omitempty"`
	Main             string               `json:"main,omitempty"`
	Files            []string             `json:"files,omitempty"`
	Scripts          map[string]string    `json:"scripts,omitempty"`
	Dist             Dist                 `json:"dist"`
	Time             map[string]time.Time `json:"time,omitempty"`
	Versions         map[string]*Package  `json:"versions,omitempty"`
	DistTags         map[string]string    `json:"dist-tags,omitempty"`
	Readme           string               `json:"readme,omitempty"`
}

// Person represents author/maintainer information
type Person struct {
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
	URL   string `json:"url,omitempty"`
}

// Repository represents repository information
type Repository struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Bugs represents bug tracking information
type Bugs struct {
	URL   string `json:"url,omitempty"`
	Email string `json:"email,omitempty"`
}

// Dist represents distribution information
type Dist struct {
	Tarball   string `json:"tarball"`
	Shasum    string `json:"shasum"`
	Integrity string `json:"integrity,omitempty"`
}

// RegistryInfo represents registry metadata
type RegistryInfo struct {
	DBName    string `json:"db_name"`
	DBVersion string `json:"db_version"`
}
