package audit

import (
	"strconv"
	"strings"

	"github.com/barelyhuman/auditor/internal/lockfile"
	"github.com/barelyhuman/auditor/internal/osv"
)

var severityRank = map[string]int{
	"info":     0,
	"low":      1,
	"moderate": 2,
	"high":     3,
	"critical": 4,
}

// FilterSafeFixes returns vulnerabilities fixable without a semver major bump.
func FilterSafeFixes(packages []lockfile.Package, vulnMap map[string][]osv.Vulnerability, minSeverity string, includeDev bool) []SafeVuln {
	minRank := severityRank[minSeverity]
	var results []SafeVuln

	for _, pkg := range packages {
		if !includeDev && pkg.Dev {
			continue
		}
		key := pkg.Name + "|" + pkg.Version
		vulns, ok := vulnMap[key]
		if !ok {
			continue
		}

		for _, v := range vulns {
			fixedVersion := extractFixedVersion(v, pkg.Name)
			if fixedVersion == "" {
				continue
			}

			if !isSafeFix(pkg.Version, fixedVersion) {
				continue
			}

			sev, score := extractSeverity(v)
			if severityRank[sev] < minRank {
				continue
			}

			cveIDs, osvIDs := extractIDs(v)

			results = append(results, SafeVuln{
				PackageName:  pkg.Name,
				Version:      pkg.Version,
				Severity:     sev,
				CVSSScore:    score,
				FixedVersion: fixedVersion,
				CVEIDs:       cveIDs,
				OSVIDs:       osvIDs,
				Summary:      v.Summary,
				AdvisoryURL:  "https://osv.dev/vulnerability/" + v.ID,
				IsDirect:     pkg.IsDirect,
				Dev:          pkg.Dev,
			})
		}
	}
	return results
}

// extractFixedVersion finds the minimum fixed version from SEMVER or ECOSYSTEM ranges.
func extractFixedVersion(v osv.Vulnerability, pkgName string) string {
	for _, affected := range v.Affected {
		if !strings.EqualFold(affected.Package.Ecosystem, "npm") {
			continue
		}
		if affected.Package.Name != pkgName {
			continue
		}
		for _, r := range affected.Ranges {
			if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			for _, event := range r.Events {
				if event.Fixed != "" {
					return event.Fixed
				}
			}
		}
	}
	return ""
}

// isSafeFix returns true if upgrading from current to fixed does not cross a major version boundary.
func isSafeFix(current, fixed string) bool {
	curMajor := majorOf(current)
	fixMajor := majorOf(fixed)
	if curMajor < 0 || fixMajor < 0 {
		// unparseable versions — allow the fix (conservative)
		return true
	}
	return curMajor == fixMajor
}

// majorOf extracts the major version integer from a semver string (strips leading 'v').
func majorOf(version string) int {
	v := strings.TrimPrefix(version, "v")
	parts := strings.SplitN(v, ".", 2)
	if len(parts) == 0 {
		return -1
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil {
		return -1
	}
	return n
}

// extractSeverity derives severity string and CVSS score from the vuln.
func extractSeverity(v osv.Vulnerability) (string, float64) {
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" || s.Type == "CVSS_V2" {
			score := parseCVSSScore(s.Score)
			return scoreToSeverity(score), score
		}
	}
	return "low", 0
}

func parseCVSSScore(score string) float64 {
	// CVSS score is embedded in vector string like "CVSS:3.1/AV:N/.../E:3.7"
	// or may be a bare float string
	parts := strings.Split(score, "/")
	// look for a standalone numeric score — sometimes it's the last segment or a dedicated field
	// OSV severity score field is the vector string; actual numeric score often not provided
	// Fall back: parse first part after "CVSS:3.x" prefix if it looks like a float
	for _, p := range parts {
		if f, err := strconv.ParseFloat(p, 64); err == nil && f >= 0 && f <= 10 {
			return f
		}
	}
	return 0
}

func scoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "moderate"
	case score > 0:
		return "low"
	default:
		return "low"
	}
}

func extractIDs(v osv.Vulnerability) (cveIDs, osvIDs []string) {
	osvIDs = append(osvIDs, v.ID)
	for _, alias := range v.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			cveIDs = append(cveIDs, alias)
		} else {
			osvIDs = append(osvIDs, alias)
		}
	}
	return
}
