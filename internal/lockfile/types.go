package lockfile

import "encoding/json"

type PackageLock struct {
	LockfileVersion int                      `json:"lockfileVersion"`
	Packages        map[string]LockedPackage `json:"packages"` // v2/v3: key = "node_modules/foo"
	Dependencies    map[string]LegacyDep     `json:"dependencies"` // v1
}

type LockedPackage struct {
	Version  string `json:"version"`
	Dev      bool   `json:"dev"`
	Peer     bool   `json:"peer"`
	Optional bool   `json:"optional"`
}

// LegacyDep is the package-lock.json v1 format
type LegacyDep struct {
	Version      string                `json:"version"`
	Dev          bool                  `json:"dev"`
	Peer         bool                  `json:"peer"`
	Optional     bool                  `json:"optional"`
	Dependencies map[string]LegacyDep  `json:"dependencies"`
}

type PackageJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	Workspaces           WorkspacesField   `json:"workspaces"`
}

// WorkspacesField handles both "workspaces": ["pkg/*"] and "workspaces": {"packages": ["pkg/*"]}
type WorkspacesField struct {
	Globs []string
}

func (w *WorkspacesField) UnmarshalJSON(data []byte) error {
	// Try array form first
	var globs []string
	if err := json.Unmarshal(data, &globs); err == nil {
		w.Globs = globs
		return nil
	}
	// Try object form: {"packages": [...]}
	var obj struct {
		Packages []string `json:"packages"`
	}
	if err := json.Unmarshal(data, &obj); err == nil {
		w.Globs = obj.Packages
		return nil
	}
	return nil // silently ignore unrecognised shape
}

type Package struct {
	Name         string
	Version      string
	IsDirect     bool
	Dev          bool
	WorkspaceDir string // relative path of workspace member that owns this dep; "" = root
}
