package lockfile

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
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

type Package struct {
	Name     string
	Version  string
	IsDirect bool
	Dev      bool
}
