package integrity

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strings"
)

// Algorithm represents a hash algorithm
type Algorithm string

const (
	SHA1   Algorithm = "sha1"
	SHA256 Algorithm = "sha256"
	SHA512 Algorithm = "sha512"
)

// Integrity represents an SRI (Subresource Integrity) hash
type Integrity struct {
	Algorithm Algorithm
	Hash      string
}

// Parse parses an SRI integrity string (e.g., "sha512-abc123...")
func Parse(integrity string) (*Integrity, error) {
	parts := strings.SplitN(integrity, "-", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid integrity format: %s", integrity)
	}

	algo := Algorithm(parts[0])
	switch algo {
	case SHA1, SHA256, SHA512:
		// Valid algorithm
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algo)
	}

	return &Integrity{
		Algorithm: algo,
		Hash:      parts[1],
	}, nil
}

// String returns the SRI string representation
func (i *Integrity) String() string {
	return fmt.Sprintf("%s-%s", i.Algorithm, i.Hash)
}

// Verify verifies that the data matches the integrity hash
func (i *Integrity) Verify(data []byte) bool {
	computed := ComputeHash(i.Algorithm, data)
	return computed == i.Hash
}

// VerifyReader verifies that the reader content matches the integrity hash
func (i *Integrity) VerifyReader(r io.Reader) (bool, error) {
	computed, err := ComputeHashReader(i.Algorithm, r)
	if err != nil {
		return false, err
	}
	return computed == i.Hash, nil
}

// ComputeHash computes a hash of the data using the specified algorithm
func ComputeHash(algo Algorithm, data []byte) string {
	var h hash.Hash

	switch algo {
	case SHA1:
		h = sha1.New()
	case SHA256:
		h = sha256.New()
	case SHA512:
		h = sha512.New()
	default:
		h = sha256.New()
	}

	h.Write(data)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// ComputeHashReader computes a hash from a reader
func ComputeHashReader(algo Algorithm, r io.Reader) (string, error) {
	var h hash.Hash

	switch algo {
	case SHA1:
		h = sha1.New()
	case SHA256:
		h = sha256.New()
	case SHA512:
		h = sha512.New()
	default:
		h = sha256.New()
	}

	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

// ComputeShasum computes a SHA-1 shasum (hex encoded) for npm compatibility
func ComputeShasum(data []byte) string {
	h := sha1.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// ComputeIntegrity computes an SRI integrity string
func ComputeIntegrity(algo Algorithm, data []byte) string {
	hash := ComputeHash(algo, data)
	return fmt.Sprintf("%s-%s", algo, hash)
}

// VerifyIntegrity verifies data against an integrity string
func VerifyIntegrity(integrity string, data []byte) (bool, error) {
	i, err := Parse(integrity)
	if err != nil {
		return false, err
	}
	return i.Verify(data), nil
}

// Verifier provides streaming verification
type Verifier struct {
	expected *Integrity
	hasher   hash.Hash
	writer   io.Writer
	verified bool
	mismatch bool
}

// NewVerifier creates a new streaming verifier
func NewVerifier(integrity string, w io.Writer) (*Verifier, error) {
	i, err := Parse(integrity)
	if err != nil {
		return nil, err
	}

	var h hash.Hash
	switch i.Algorithm {
	case SHA1:
		h = sha1.New()
	case SHA256:
		h = sha256.New()
	case SHA512:
		h = sha512.New()
	default:
		h = sha256.New()
	}

	return &Verifier{
		expected: i,
		hasher:   h,
		writer:   w,
	}, nil
}

// Write implements io.Writer, writing to both the hasher and underlying writer
func (v *Verifier) Write(p []byte) (n int, err error) {
	n, err = v.hasher.Write(p)
	if err != nil {
		return n, err
	}

	if v.writer != nil {
		return v.writer.Write(p)
	}

	return n, nil
}

// Verify checks if the written data matches the expected integrity
func (v *Verifier) Verify() bool {
	if v.verified {
		return !v.mismatch
	}

	computed := base64.StdEncoding.EncodeToString(v.hasher.Sum(nil))
	v.verified = true
	v.mismatch = computed != v.expected.Hash

	return !v.mismatch
}
