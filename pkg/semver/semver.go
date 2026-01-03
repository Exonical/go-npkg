package semver

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Version represents a parsed semantic version
type Version struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string
	Build      string
	Original   string
}

var (
	// semverRegex matches semantic versions
	semverRegex = regexp.MustCompile(`^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z\-\.]+))?(?:\+([0-9A-Za-z\-\.]+))?$`)
)

// Parse parses a version string into a Version struct
func Parse(version string) (*Version, error) {
	version = strings.TrimSpace(version)
	matches := semverRegex.FindStringSubmatch(version)
	if matches == nil {
		return nil, fmt.Errorf("invalid version: %s", version)
	}

	v := &Version{Original: version}

	v.Major, _ = strconv.Atoi(matches[1])
	if matches[2] != "" {
		v.Minor, _ = strconv.Atoi(matches[2])
	}
	if matches[3] != "" {
		v.Patch, _ = strconv.Atoi(matches[3])
	}
	if matches[4] != "" {
		v.Prerelease = matches[4]
	}
	if matches[5] != "" {
		v.Build = matches[5]
	}

	return v, nil
}

// String returns the version as a string
func (v *Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Prerelease != "" {
		s += "-" + v.Prerelease
	}
	if v.Build != "" {
		s += "+" + v.Build
	}
	return s
}

// Compare compares two versions
// Returns -1 if v < other, 0 if v == other, 1 if v > other
func (v *Version) Compare(other *Version) int {
	if v.Major != other.Major {
		return compareInt(v.Major, other.Major)
	}
	if v.Minor != other.Minor {
		return compareInt(v.Minor, other.Minor)
	}
	if v.Patch != other.Patch {
		return compareInt(v.Patch, other.Patch)
	}

	// Prerelease versions have lower precedence
	if v.Prerelease == "" && other.Prerelease != "" {
		return 1
	}
	if v.Prerelease != "" && other.Prerelease == "" {
		return -1
	}
	if v.Prerelease != other.Prerelease {
		return comparePrerelease(v.Prerelease, other.Prerelease)
	}

	return 0
}

// LessThan returns true if v < other
func (v *Version) LessThan(other *Version) bool {
	return v.Compare(other) < 0
}

// GreaterThan returns true if v > other
func (v *Version) GreaterThan(other *Version) bool {
	return v.Compare(other) > 0
}

// Equal returns true if v == other
func (v *Version) Equal(other *Version) bool {
	return v.Compare(other) == 0
}

func compareInt(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func comparePrerelease(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	for i := 0; i < len(aParts) && i < len(bParts); i++ {
		aNum, aErr := strconv.Atoi(aParts[i])
		bNum, bErr := strconv.Atoi(bParts[i])

		if aErr == nil && bErr == nil {
			if aNum != bNum {
				return compareInt(aNum, bNum)
			}
		} else if aErr == nil {
			return -1 // numeric < alphanumeric
		} else if bErr == nil {
			return 1
		} else {
			if aParts[i] < bParts[i] {
				return -1
			}
			if aParts[i] > bParts[i] {
				return 1
			}
		}
	}

	return compareInt(len(aParts), len(bParts))
}

// Range represents a version range/constraint
type Range struct {
	constraints []constraint
}

type constraint struct {
	op      string
	version *Version
}

// ParseRange parses a version range string (supports npm-style ranges)
func ParseRange(rangeStr string) (*Range, error) {
	rangeStr = strings.TrimSpace(rangeStr)

	// Handle special cases
	if rangeStr == "" || rangeStr == "*" || rangeStr == "latest" {
		return &Range{constraints: []constraint{{op: "*"}}}, nil
	}

	// Handle caret range (^)
	if strings.HasPrefix(rangeStr, "^") {
		return parseCaretRange(rangeStr[1:])
	}

	// Handle tilde range (~)
	if strings.HasPrefix(rangeStr, "~") {
		return parseTildeRange(rangeStr[1:])
	}

	// Handle comparison operators
	for _, op := range []string{">=", "<=", ">", "<", "="} {
		if strings.HasPrefix(rangeStr, op) {
			v, err := Parse(strings.TrimPrefix(rangeStr, op))
			if err != nil {
				return nil, err
			}
			return &Range{constraints: []constraint{{op: op, version: v}}}, nil
		}
	}

	// Handle hyphen range (1.0.0 - 2.0.0)
	if strings.Contains(rangeStr, " - ") {
		return parseHyphenRange(rangeStr)
	}

	// Handle x-range (1.x, 1.2.x)
	if strings.Contains(rangeStr, "x") || strings.Contains(rangeStr, "X") {
		return parseXRange(rangeStr)
	}

	// Exact version
	v, err := Parse(rangeStr)
	if err != nil {
		return nil, err
	}
	return &Range{constraints: []constraint{{op: "=", version: v}}}, nil
}

func parseCaretRange(versionStr string) (*Range, error) {
	v, err := Parse(versionStr)
	if err != nil {
		return nil, err
	}

	// ^1.2.3 := >=1.2.3 <2.0.0
	// ^0.2.3 := >=0.2.3 <0.3.0
	// ^0.0.3 := >=0.0.3 <0.0.4
	var upper *Version
	if v.Major != 0 {
		upper = &Version{Major: v.Major + 1, Minor: 0, Patch: 0}
	} else if v.Minor != 0 {
		upper = &Version{Major: 0, Minor: v.Minor + 1, Patch: 0}
	} else {
		upper = &Version{Major: 0, Minor: 0, Patch: v.Patch + 1}
	}

	return &Range{
		constraints: []constraint{
			{op: ">=", version: v},
			{op: "<", version: upper},
		},
	}, nil
}

func parseTildeRange(versionStr string) (*Range, error) {
	v, err := Parse(versionStr)
	if err != nil {
		return nil, err
	}

	// ~1.2.3 := >=1.2.3 <1.3.0
	upper := &Version{Major: v.Major, Minor: v.Minor + 1, Patch: 0}

	return &Range{
		constraints: []constraint{
			{op: ">=", version: v},
			{op: "<", version: upper},
		},
	}, nil
}

func parseHyphenRange(rangeStr string) (*Range, error) {
	parts := strings.Split(rangeStr, " - ")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid hyphen range: %s", rangeStr)
	}

	lower, err := Parse(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, err
	}

	upper, err := Parse(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, err
	}

	return &Range{
		constraints: []constraint{
			{op: ">=", version: lower},
			{op: "<=", version: upper},
		},
	}, nil
}

func parseXRange(rangeStr string) (*Range, error) {
	rangeStr = strings.ToLower(rangeStr)
	parts := strings.Split(rangeStr, ".")

	if parts[0] == "x" {
		return &Range{constraints: []constraint{{op: "*"}}}, nil
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid x-range: %s", rangeStr)
	}

	if len(parts) == 1 || parts[1] == "x" {
		// 1.x := >=1.0.0 <2.0.0
		return &Range{
			constraints: []constraint{
				{op: ">=", version: &Version{Major: major, Minor: 0, Patch: 0}},
				{op: "<", version: &Version{Major: major + 1, Minor: 0, Patch: 0}},
			},
		}, nil
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid x-range: %s", rangeStr)
	}

	if len(parts) == 2 || parts[2] == "x" {
		// 1.2.x := >=1.2.0 <1.3.0
		return &Range{
			constraints: []constraint{
				{op: ">=", version: &Version{Major: major, Minor: minor, Patch: 0}},
				{op: "<", version: &Version{Major: major, Minor: minor + 1, Patch: 0}},
			},
		}, nil
	}

	return nil, fmt.Errorf("invalid x-range: %s", rangeStr)
}

// Satisfies checks if a version satisfies the range
func (r *Range) Satisfies(v *Version) bool {
	for _, c := range r.constraints {
		if !c.satisfies(v) {
			return false
		}
	}
	return true
}

func (c *constraint) satisfies(v *Version) bool {
	switch c.op {
	case "*":
		return true
	case "=":
		return v.Equal(c.version)
	case ">":
		return v.GreaterThan(c.version)
	case ">=":
		return v.GreaterThan(c.version) || v.Equal(c.version)
	case "<":
		return v.LessThan(c.version)
	case "<=":
		return v.LessThan(c.version) || v.Equal(c.version)
	default:
		return false
	}
}

// MaxSatisfying returns the highest version that satisfies the range
func MaxSatisfying(versions []string, rangeStr string) (string, error) {
	r, err := ParseRange(rangeStr)
	if err != nil {
		return "", err
	}

	var matching []*Version
	for _, vs := range versions {
		v, err := Parse(vs)
		if err != nil {
			continue
		}
		if r.Satisfies(v) {
			matching = append(matching, v)
		}
	}

	if len(matching) == 0 {
		return "", fmt.Errorf("no matching version for %s", rangeStr)
	}

	// Sort descending
	sort.Slice(matching, func(i, j int) bool {
		return matching[i].GreaterThan(matching[j])
	})

	return matching[0].String(), nil
}

// SortVersions sorts version strings in descending order (newest first)
func SortVersions(versions []string) []string {
	parsed := make([]*Version, 0, len(versions))
	for _, vs := range versions {
		v, err := Parse(vs)
		if err != nil {
			continue
		}
		parsed = append(parsed, v)
	}

	sort.Slice(parsed, func(i, j int) bool {
		return parsed[i].GreaterThan(parsed[j])
	})

	result := make([]string, len(parsed))
	for i, v := range parsed {
		result[i] = v.String()
	}
	return result
}

// Valid checks if a string is a valid semver
func Valid(version string) bool {
	_, err := Parse(version)
	return err == nil
}
