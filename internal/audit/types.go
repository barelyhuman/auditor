package audit

type SafeVuln struct {
	PackageName  string
	Version      string
	Severity     string
	CVSSScore    float64
	FixedVersion string
	CVEIDs       []string
	OSVIDs       []string
	Summary      string
	AdvisoryURL  string
	IsDirect     bool
	Dev          bool
}
