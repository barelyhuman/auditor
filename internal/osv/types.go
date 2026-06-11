package osv

// QueryBatch request/response

type BatchRequest struct {
	Queries []Query `json:"queries"`
}

type Query struct {
	Version string  `json:"version"`
	Package PkgRef  `json:"package"`
}

type PkgRef struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type BatchResponse struct {
	Results []QueryResult `json:"results"`
}

type QueryResult struct {
	Vulns         []VulnRef `json:"vulns"`
	NextPageToken string    `json:"next_page_token,omitempty"`
}

type VulnRef struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

// Full vulnerability detail from GET /v1/vulns/{id}

type Vulnerability struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Severity []Severity `json:"severity"`
	Affected []Affected `json:"affected"`
}

type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type Affected struct {
	Package AffectedPackage `json:"package"`
	Ranges  []Range         `json:"ranges"`
}

type AffectedPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type Range struct {
	Type   string       `json:"type"` // SEMVER, ECOSYSTEM, GIT
	Events []RangeEvent `json:"events"`
}

type RangeEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}
