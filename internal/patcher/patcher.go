package patcher

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/barelyhuman/auditor/internal/audit"
	"github.com/barelyhuman/auditor/internal/registry"
)

type PatchResult struct {
	PackageName        string
	OldVersion         string
	NewVersion         string
	PatchedKeys        []string
	PackageJSONUpdated bool
	Err                error
}

// PatchPackages updates package-lock.json (and package.json for direct deps)
// for each selected vulnerability. Uses surgical JSON map manipulation to
// preserve all unrelated fields.
func PatchPackages(dir string, vulns []audit.SafeVuln, dryRun bool) ([]PatchResult, error) {
	lockPath := filepath.Join(dir, "package-lock.json")
	pkgPath := filepath.Join(dir, "package.json")

	// Read lockfile as raw JSON to preserve unknown fields
	lockRaw, err := readRawLock(lockPath)
	if err != nil {
		return nil, err
	}

	pkgRaw, err := readRawPkg(pkgPath)
	if err != nil {
		return nil, err
	}

	// Extract "packages" map (v2/v3) — each entry is itself a raw field map
	packagesRaw, hasPackages, err := extractPackagesMap(lockRaw)
	if err != nil {
		return nil, err
	}

	var results []PatchResult

	for _, v := range vulns {
		res := PatchResult{
			PackageName: v.PackageName,
			OldVersion:  v.Version,
			NewVersion:  v.FixedVersion,
		}

		// Fetch registry metadata for the fixed version
		dist, err := registry.FetchDist(v.PackageName, v.FixedVersion)
		if err != nil {
			res.Err = err
			results = append(results, res)
			continue
		}

		if hasPackages {
			patched := patchPackagesMap(packagesRaw, v.PackageName, v.Version, dist)
			res.PatchedKeys = patched
		}

		// Update package.json if direct dep
		if v.IsDirect {
			updated := updatePackageJSON(pkgRaw, v.PackageName, v.FixedVersion, v.Dev)
			res.PackageJSONUpdated = updated
		}

		results = append(results, res)
	}

	if dryRun {
		printDryRun(results)
		return results, nil
	}

	// Write lockfile back
	if hasPackages {
		if err := writeLock(lockPath, lockRaw, packagesRaw); err != nil {
			return nil, fmt.Errorf("write package-lock.json: %w", err)
		}
	}

	// Write package.json back if modified
	anyDirect := false
	for _, r := range results {
		if r.PackageJSONUpdated {
			anyDirect = true
			break
		}
	}
	if anyDirect {
		if err := writePkg(pkgPath, pkgRaw); err != nil {
			return nil, fmt.Errorf("write package.json: %w", err)
		}
	}

	return results, nil
}

// patchPackagesMap updates all lockfile entries for pkgName@oldVersion in-place.
// Returns list of keys that were patched.
func patchPackagesMap(packages map[string]map[string]json.RawMessage, pkgName, oldVersion string, dist *registry.DistInfo) []string {
	suffix := "node_modules/" + pkgName
	var patched []string

	for key, entry := range packages {
		if !strings.HasSuffix(key, suffix) {
			continue
		}

		// Only patch entries at the vulnerable version
		var entryVersion string
		if raw, ok := entry["version"]; ok {
			_ = json.Unmarshal(raw, &entryVersion)
		}
		if entryVersion != oldVersion {
			continue
		}

		entry["version"] = mustMarshal(dist.Version)
		entry["resolved"] = mustMarshal(dist.Tarball)
		entry["integrity"] = mustMarshal(dist.Integrity)
		packages[key] = entry
		patched = append(patched, key)
	}

	return patched
}

// updatePackageJSON bumps the version range in dependencies or devDependencies.
func updatePackageJSON(pkg map[string]json.RawMessage, name, fixedVersion string, _ bool) bool {
	sections := []string{"dependencies", "devDependencies"}
	for _, section := range sections {
		raw, ok := pkg[section]
		if !ok {
			continue
		}
		var deps map[string]json.RawMessage
		if err := json.Unmarshal(raw, &deps); err != nil {
			continue
		}
		existing, ok := deps[name]
		if !ok {
			continue
		}

		var current string
		_ = json.Unmarshal(existing, &current)

		// Preserve range prefix (^, ~, >=, exact)
		prefix := rangePrefix(current)
		deps[name] = mustMarshal(prefix + fixedVersion)

		updated, err := json.Marshal(deps)
		if err == nil {
			pkg[section] = updated
		}
		return true
	}
	return false
}

func rangePrefix(version string) string {
	for _, p := range []string{">=", "~", "^"} {
		if strings.HasPrefix(version, p) {
			return p
		}
	}
	return ""
}

// --- JSON helpers ---

func readRawLock(path string) (map[string]json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read package-lock.json: %w", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}
	return raw, nil
}

func readRawPkg(path string) (map[string]json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read package.json: %w", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}
	return raw, nil
}

func extractPackagesMap(lock map[string]json.RawMessage) (map[string]map[string]json.RawMessage, bool, error) {
	packagesJSON, ok := lock["packages"]
	if !ok {
		return nil, false, nil
	}
	var raw map[string]map[string]json.RawMessage
	if err := json.Unmarshal(packagesJSON, &raw); err != nil {
		return nil, false, fmt.Errorf("parse packages map: %w", err)
	}
	return raw, true, nil
}

func writeLock(path string, lock map[string]json.RawMessage, packages map[string]map[string]json.RawMessage) error {
	pkgJSON, err := marshalNoEscape(packages)
	if err != nil {
		return err
	}
	lock["packages"] = pkgJSON
	out, err := marshalIndentNoEscape(lock)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0644)
}

func writePkg(path string, pkg map[string]json.RawMessage) error {
	out, err := marshalIndentNoEscape(pkg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0644)
}

func mustMarshal(v string) json.RawMessage {
	b, err := marshalNoEscape(v)
	if err != nil {
		b, _ = json.Marshal(v)
	}
	return b
}

func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encode appends a trailing newline; trim it
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func marshalIndentNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
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
			fmt.Printf("      lockfile key: %s\n", k)
		}
		if r.PackageJSONUpdated {
			fmt.Printf("      package.json: updated\n")
		}
	}
}
