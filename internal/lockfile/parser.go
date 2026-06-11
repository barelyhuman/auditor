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

	// Root direct deps (all declared dep sections)
	rootDirect := make(map[string]bool)
	for name := range pkgJSON.Dependencies {
		rootDirect[name] = true
	}
	for name := range pkgJSON.DevDependencies {
		rootDirect[name] = true
	}
	for name := range pkgJSON.PeerDependencies {
		rootDirect[name] = true
	}
	for name := range pkgJSON.OptionalDependencies {
		rootDirect[name] = true
	}

	// Workspace member direct deps: package name → workspace dir
	workspaceDirect := make(map[string]string)
	if lock.LockfileVersion >= 2 {
		for key := range lock.Packages {
			if key == "" || strings.HasPrefix(key, "node_modules/") {
				continue
			}
			// key is a workspace member path like "packages/foo"
			memberPkg, err := readPackageJSON(filepath.Join(dir, key))
			if err != nil {
				continue // member missing package.json — skip
			}
			for _, depMap := range []map[string]string{
				memberPkg.Dependencies,
				memberPkg.DevDependencies,
				memberPkg.PeerDependencies,
				memberPkg.OptionalDependencies,
			} {
				for name := range depMap {
					if _, alreadyRoot := rootDirect[name]; !alreadyRoot {
						workspaceDirect[name] = key
					}
				}
			}
		}
	}

	if lock.LockfileVersion >= 2 {
		return parseV2(lock, rootDirect, workspaceDirect), nil
	}
	return parseV1(lock, rootDirect), nil
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
func parseV2(lock PackageLock, rootDirect map[string]bool, workspaceDirect map[string]string) []Package {
	seen := make(map[string]bool)
	var pkgs []Package

	for key, lp := range lock.Packages {
		if key == "" || !strings.HasPrefix(key, "node_modules/") {
			continue // skip root and workspace member entries
		}

		name := nameFromKey(key)
		if name == "" || seen[name+"|"+lp.Version] {
			continue
		}
		seen[name+"|"+lp.Version] = true

		isDirect := rootDirect[name]
		workspaceDir := ""
		if !isDirect {
			if wsDir, ok := workspaceDirect[name]; ok {
				isDirect = true
				workspaceDir = wsDir
			}
		}

		pkgs = append(pkgs, Package{
			Name:         name,
			Version:      lp.Version,
			IsDirect:     isDirect,
			Dev:          lp.Dev || lp.Peer,
			WorkspaceDir: workspaceDir,
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

// WorkspaceMemberDirs returns all workspace member paths found in the lockfile packages map.
// These are keys that are not "" and don't start with "node_modules/".
func WorkspaceMemberDirs(lockPath string) ([]string, error) {
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, err
	}
	var lock PackageLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	var dirs []string
	for key := range lock.Packages {
		if key != "" && !strings.HasPrefix(key, "node_modules/") {
			dirs = append(dirs, key)
		}
	}
	return dirs, nil
}
