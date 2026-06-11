package audit

import (
	"encoding/json"
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
// Priority: database_specific.severity string → CVSS vector computation.
func extractSeverity(v osv.Vulnerability) (string, float64) {
	// GitHub/NVD advisory data often provides a pre-computed severity string.
	if raw, ok := v.DatabaseSpecific["severity"]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil && s != "" {
			return normalizeSeverity(s), 0
		}
	}
	// Fall back: compute base score from CVSS vector string.
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" || s.Type == "CVSS_V2" {
			score := cvssBaseScore(s.Score)
			if score > 0 {
				return scoreToSeverity(score), score
			}
		}
	}
	return "low", 0
}

func normalizeSeverity(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MODERATE", "MEDIUM":
		return "moderate"
	default:
		return "low"
	}
}

// cvssBaseScore computes the CVSS 3.x base score from a vector string.
// Vector format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
func cvssBaseScore(vector string) float64 {
	metrics := parseCVSSVector(vector)
	if len(metrics) == 0 {
		return 0
	}

	// Impact sub-score weights (CVSS 3.1 spec table 12)
	c := impactWeight(metrics["C"])
	i := impactWeight(metrics["I"])
	a := impactWeight(metrics["A"])

	iss := 1 - (1-c)*(1-i)*(1-a)

	scope := metrics["S"]
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*pow(iss-0.02, 15)
	}

	if impact <= 0 {
		return 0
	}

	avW := avWeight(metrics["AV"])
	acW := acWeight(metrics["AC"])
	prW := prWeight(metrics["PR"], scope == "C")
	uiW := uiWeight(metrics["UI"])

	exploitability := 8.22 * avW * acW * prW * uiW

	var base float64
	if scope == "U" {
		base = roundUp(min10(impact + exploitability))
	} else {
		base = roundUp(min10(1.08 * (impact + exploitability)))
	}
	return base
}

func parseCVSSVector(vector string) map[string]string {
	metrics := make(map[string]string)
	parts := strings.Split(vector, "/")
	for _, p := range parts {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}
	return metrics
}

func impactWeight(v string) float64 {
	switch v {
	case "N":
		return 0
	case "L":
		return 0.22
	case "H":
		return 0.56
	}
	return 0
}

func avWeight(v string) float64 {
	switch v {
	case "N":
		return 0.85
	case "A":
		return 0.62
	case "L":
		return 0.55
	case "P":
		return 0.2
	}
	return 0.85
}

func acWeight(v string) float64 {
	if v == "H" {
		return 0.44
	}
	return 0.77
}

func prWeight(v string, scopeChanged bool) float64 {
	if scopeChanged {
		switch v {
		case "N":
			return 0.85
		case "L":
			return 0.68
		case "H":
			return 0.50
		}
	} else {
		switch v {
		case "N":
			return 0.85
		case "L":
			return 0.62
		case "H":
			return 0.27
		}
	}
	return 0.85
}

func uiWeight(v string) float64 {
	if v == "R" {
		return 0.62
	}
	return 0.85
}

func roundUp(x float64) float64 {
	// Round up to 1 decimal place (CVSS 3.1 spec)
	return float64(int(x*10+0.999999)) / 10
}

func min10(x float64) float64 {
	if x > 10 {
		return 10
	}
	return x
}

func pow(base, exp float64) float64 {
	result := 1.0
	for i := 0; i < int(exp); i++ {
		result *= base
	}
	return result
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
