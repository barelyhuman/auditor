package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const registryURL = "https://registry.npmjs.org"

var httpClient = &http.Client{Timeout: 15 * time.Second}

type DistInfo struct {
	Integrity string
	Tarball   string
	Version   string
}

type versionMeta struct {
	Version string `json:"version"`
	Dist    struct {
		Integrity string `json:"integrity"`
		Tarball   string `json:"tarball"`
	} `json:"dist"`
}

// FetchDist fetches integrity hash and tarball URL for a specific package version.
func FetchDist(name, version string) (*DistInfo, error) {
	url := fmt.Sprintf("%s/%s/%s", registryURL, encodeName(name), version)
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("registry fetch %s@%s: %w", name, version, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package %s@%s not found in registry", name, version)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registry HTTP %d for %s@%s: %s", resp.StatusCode, name, version, string(b))
	}

	var meta versionMeta
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("parse registry response for %s@%s: %w", name, version, err)
	}

	if meta.Dist.Integrity == "" {
		return nil, fmt.Errorf("no integrity hash in registry for %s@%s", name, version)
	}

	return &DistInfo{
		Integrity: meta.Dist.Integrity,
		Tarball:   meta.Dist.Tarball,
		Version:   meta.Version,
	}, nil
}

// FetchVersions returns all published versions for a package.
func FetchVersions(name string) ([]string, error) {
	url := fmt.Sprintf("%s/%s", registryURL, encodeName(name))
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("registry fetch versions %s: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registry HTTP %d for %s: %s", resp.StatusCode, name, string(b))
	}

	var root struct {
		Versions map[string]json.RawMessage `json:"versions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&root); err != nil {
		return nil, fmt.Errorf("parse versions for %s: %w", name, err)
	}

	versions := make([]string, 0, len(root.Versions))
	for v := range root.Versions {
		versions = append(versions, v)
	}
	return versions, nil
}

// MinSafeVersion finds the lowest published version >= minVersion within the same
// semver major as installedVersion. Implements minimum-bump policy to avoid
// installing unnecessarily new code.
func MinSafeVersion(name, installedVersion, minVersion string) (string, error) {
	allVersions, err := FetchVersions(name)
	if err != nil {
		return "", err
	}

	installedMajor := semverMajor(installedVersion)

	var candidates []string
	for _, v := range allVersions {
		if semverMajor(v) != installedMajor {
			continue
		}
		if semverGTE(v, minVersion) {
			candidates = append(candidates, v)
		}
	}

	if len(candidates) == 0 {
		return "", fmt.Errorf("no safe version >= %s in same major as %s for %s", minVersion, installedVersion, name)
	}

	sort.Slice(candidates, func(i, j int) bool {
		return SemverLess(candidates[i], candidates[j])
	})

	return candidates[0], nil
}

// --- Semver helpers (no external deps) ---

// parseSemver parses "major.minor.patch[-prerelease]" into [3]int.
// Returns [-1,-1,-1] on failure.
func parseSemver(v string) [3]int {
	v = strings.TrimPrefix(v, "v")
	// strip pre-release/build metadata
	if idx := strings.IndexAny(v, "-+"); idx != -1 {
		v = v[:idx]
	}
	parts := strings.SplitN(v, ".", 3)
	var nums [3]int
	for i := range min(3, len(parts)) {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return [3]int{-1, -1, -1}
		}
		nums[i] = n
	}
	return nums
}

func semverMajor(v string) int {
	return parseSemver(v)[0]
}

// SemverLess returns true if a < b.
func SemverLess(a, b string) bool {
	pa, pb := parseSemver(a), parseSemver(b)
	for i := range 3 {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

// semverGTE returns true if a >= b.
func semverGTE(a, b string) bool {
	return !SemverLess(a, b)
}

// encodeName URL-encodes scoped package names (e.g. @scope/pkg → @scope%2Fpkg).
func encodeName(name string) string {
	if len(name) > 0 && name[0] == '@' {
		for i := 1; i < len(name); i++ {
			if name[i] == '/' {
				return name[:i] + "%2F" + name[i+1:]
			}
		}
	}
	return name
}
