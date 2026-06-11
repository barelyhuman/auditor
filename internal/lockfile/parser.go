package lockfile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func ReadPackages(dir string) ([]Package, error) {
	pkgJSON, err := readPackageJSON(dir)
	if err != nil {
		return nil, err
	}

	lockData, err := os.ReadFile(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("package-lock.json not found — run `npm install` first")
		}
		return nil, fmt.Errorf("read package-lock.json: %w", err)
	}

	var lock PackageLock
	if err := json.Unmarshal(lockData, &lock); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}

	directDeps := make(map[string]bool)
	for name := range pkgJSON.Dependencies {
		directDeps[name] = true
	}
	for name := range pkgJSON.DevDependencies {
		directDeps[name] = true
	}

	if lock.LockfileVersion >= 2 {
		return parseV2(lock, directDeps), nil
	}
	return parseV1(lock, directDeps), nil
}

func readPackageJSON(dir string) (*PackageJSON, error) {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("package.json not found — not a Node.js project")
		}
		return nil, fmt.Errorf("read package.json: %w", err)
	}
	var pkg PackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}
	return &pkg, nil
}

// parseV2 handles lockfileVersion 2 and 3 (packages map)
func parseV2(lock PackageLock, directDeps map[string]bool) []Package {
	seen := make(map[string]bool)
	var pkgs []Package

	for key, lp := range lock.Packages {
		if key == "" {
			continue // root entry
		}

		name := nameFromKey(key)
		if name == "" || seen[name+"|"+lp.Version] {
			continue
		}
		seen[name+"|"+lp.Version] = true

		pkgs = append(pkgs, Package{
			Name:     name,
			Version:  lp.Version,
			IsDirect: directDeps[name],
			Dev:      lp.Dev || lp.Peer,
		})
	}
	return pkgs
}

// parseV1 handles lockfileVersion 1 (dependencies map, recursive)
func parseV1(lock PackageLock, directDeps map[string]bool) []Package {
	seen := make(map[string]bool)
	var pkgs []Package
	collectV1(lock.Dependencies, directDeps, seen, &pkgs)
	return pkgs
}

func collectV1(deps map[string]LegacyDep, directDeps, seen map[string]bool, out *[]Package) {
	for name, dep := range deps {
		key := name + "|" + dep.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		*out = append(*out, Package{
			Name:     name,
			Version:  dep.Version,
			IsDirect: directDeps[name],
			Dev:      dep.Dev || dep.Peer,
		})
		if len(dep.Dependencies) > 0 {
			collectV1(dep.Dependencies, directDeps, seen, out)
		}
	}
}

// nameFromKey extracts package name from "node_modules/foo" or "node_modules/@scope/foo"
func nameFromKey(key string) string {
	const prefix = "node_modules/"
	// find last occurrence to handle nested: node_modules/a/node_modules/b
	idx := strings.LastIndex(key, prefix)
	if idx == -1 {
		return ""
	}
	return key[idx+len(prefix):]
}
