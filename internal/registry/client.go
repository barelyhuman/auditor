package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
