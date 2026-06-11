package patcher

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/barelyhuman/auditor/internal/audit"
	"github.com/barelyhuman/auditor/internal/lockfile"
	"github.com/barelyhuman/auditor/internal/registry"
	"github.com/tidwall/sjson"
)

type PatchResult struct {
	PackageName      string
	OldVersion       string
	NewVersion       string
	PatchedKeys      []string
	PackageJSONPaths []string // package.json files updated (root + workspace members)
	Err              error
}

// PatchPackages updates package-lock.json and all relevant package.json files.
// Uses sjson for surgical in-place writes — preserves key order and formatting.
func PatchPackages(dir string, vulns []audit.SafeVuln, dryRun bool) ([]PatchResult, error) {
	lockPath := filepath.Join(dir, "package-lock.json")

	workspaceDirs, _ := lockfile.WorkspaceMemberDirs(lockPath)

	allPkgPaths := []string{filepath.Join(dir, "package.json")}
	for _, wsDir := range workspaceDirs {
		allPkgPaths = append(allPkgPaths, filepath.Join(dir, wsDir, "package.json"))
	}

	// Deduplicate: multiple CVEs for same name@version → keep max FixedVersion.
	// Without this, a lower-FixedVersion CVE processed last would overwrite package.json
	// with a still-vulnerable version while the lockfile already has the correct higher version.
	bestFix := make(map[string]audit.SafeVuln) // key = "name@version"
	for _, v := range vulns {
		key := v.PackageName + "@" + v.Version
		if existing, ok := bestFix[key]; !ok || registry.SemverLess(existing.FixedVersion, v.FixedVersion) {
			bestFix[key] = v
		}
	}
	deduped := make([]audit.SafeVuln, 0, len(bestFix))
	for _, v := range bestFix {
		deduped = append(deduped, v)
	}

	var results []PatchResult

	for _, v := range deduped {
		res := PatchResult{
			PackageName: v.PackageName,
			OldVersion:  v.Version,
			NewVersion:  v.FixedVersion,
		}

		// Resolve minimum published version >= OSV's fixed, within same major as installed.
		safeVer, err := registry.MinSafeVersion(v.PackageName, v.Version, v.FixedVersion)
		if err != nil {
			res.Err = fmt.Errorf("no safe version for %s: %w", v.PackageName, err)
			results = append(results, res)
			continue
		}
		dist, err := registry.FetchDist(v.PackageName, safeVer)
		if err != nil {
			res.Err = err
			results = append(results, res)
			continue
		}
		res.NewVersion = dist.Version

		// Patch lockfile
		patched, err := patchLockfileInPlace(lockPath, v.PackageName, v.Version, dist, dryRun)
		if err != nil {
			res.Err = err
			results = append(results, res)
			continue
		}
		res.PatchedKeys = patched

		// Patch package.json files for direct deps
		if v.IsDirect {
			for _, pkgPath := range allPkgPaths {
				updated, err := updatePkgFileInPlace(pkgPath, v.PackageName, dist.Version, dryRun)
				if err != nil {
					// Non-fatal: file may not exist (workspace member without this dep)
					continue
				}
				if updated {
					res.PackageJSONPaths = append(res.PackageJSONPaths, pkgPath)
				}
			}
		}

		results = append(results, res)
	}

	if dryRun {
		printDryRun(results)
	}
	return results, nil
}

// patchLockfileInPlace surgically updates version/resolved/integrity for matching entries.
// Uses sjson to preserve key order and formatting.
func patchLockfileInPlace(lockPath, pkgName, oldVersion string, dist *registry.DistInfo, dryRun bool) ([]string, error) {
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("read package-lock.json: %w", err)
	}

	// Partial unmarshal to find matching keys (read-only)
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}

	suffix := "node_modules/" + pkgName
	var patched []string

	for key, entry := range lock.Packages {
		if !strings.HasSuffix(key, suffix) || entry.Version != oldVersion {
			continue
		}
		base := "packages." + key
		data, _ = sjson.SetBytes(data, base+".version", dist.Version)
		data, _ = sjson.SetBytes(data, base+".resolved", dist.Tarball)
		data, _ = sjson.SetBytes(data, base+".integrity", dist.Integrity)
		patched = append(patched, key)
	}

	if len(patched) > 0 && !dryRun {
		if err := os.WriteFile(lockPath, data, 0644); err != nil {
			return nil, fmt.Errorf("write package-lock.json: %w", err)
		}
	}
	return patched, nil
}

// updatePkgFileInPlace surgically bumps one dependency version in a package.json.
// Preserves key order, whitespace, and all other fields.
func updatePkgFileInPlace(path, name, fixedVersion string, dryRun bool) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, nil // file doesn't exist — skip silently
	}

	// Partial unmarshal to detect section and current version prefix
	var pkg struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return false, fmt.Errorf("parse %s: %w", path, err)
	}

	sections := []struct {
		key  string
		deps map[string]string
	}{
		{"dependencies", pkg.Dependencies},
		{"devDependencies", pkg.DevDependencies},
		{"peerDependencies", pkg.PeerDependencies},
		{"optionalDependencies", pkg.OptionalDependencies},
	}

	var sectionPath string
	var prefix string
	for _, s := range sections {
		if current, ok := s.deps[name]; ok {
			sectionPath = s.key + "." + name
			prefix = rangePrefix(current)
			break
		}
	}
	if sectionPath == "" {
		return false, nil // not in this file
	}

	updated, err := sjson.SetBytes(data, sectionPath, prefix+fixedVersion)
	if err != nil {
		return false, fmt.Errorf("sjson set %s in %s: %w", sectionPath, path, err)
	}

	if !dryRun {
		if err := os.WriteFile(path, updated, 0644); err != nil {
			return false, fmt.Errorf("write %s: %w", path, err)
		}
	}
	return true, nil
}

func rangePrefix(version string) string {
	for _, p := range []string{">=", "~", "^"} {
		if strings.HasPrefix(version, p) {
			return p
		}
	}
	return ""
}

func printDryRun(results []PatchResult) {
	fmt.Println("\n[dry-run] Changes that would be applied:")
	for _, r := range results {
		if r.Err != nil {
			fmt.Printf("  ✗ %s: %v\n", r.PackageName, r.Err)
			continue
		}
		fmt.Printf("  %s: %s → %s\n", r.PackageName, r.OldVersion, r.NewVersion)
		for _, k := range r.PatchedKeys {
			fmt.Printf("      lockfile: %s\n", k)
		}
		for _, p := range r.PackageJSONPaths {
			fmt.Printf("      package.json: %s\n", p)
		}
	}
}
