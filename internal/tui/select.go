package tui

import (
	"fmt"
	"sort"

	"github.com/barelyhuman/auditor/internal/audit"
	"github.com/charmbracelet/huh"
)

var severityRank = map[string]int{
	"info": 0, "low": 1, "moderate": 2, "high": 3, "critical": 4,
}

// SelectPackages shows an interactive multi-select TUI and returns the chosen vulns.
func SelectPackages(vulns []audit.SafeVuln) ([]audit.SafeVuln, error) {
	if len(vulns) == 0 {
		return nil, nil
	}

	sorted := make([]audit.SafeVuln, len(vulns))
	copy(sorted, vulns)
	sort.Slice(sorted, func(i, j int) bool {
		ri := severityRank[sorted[i].Severity]
		rj := severityRank[sorted[j].Severity]
		if ri != rj {
			return ri > rj // critical first
		}
		return sorted[i].PackageName < sorted[j].PackageName
	})

	opts := make([]huh.Option[string], len(sorted))
	for i, v := range sorted {
		cves := ""
		if len(v.CVEIDs) > 0 {
			cves = "  " + v.CVEIDs[0]
		}
		label := fmt.Sprintf("%-8s  %-30s  %s → %s%s",
			v.Severity, v.PackageName, v.Version, v.FixedVersion, cves)
		opts[i] = huh.NewOption(label, v.PackageName+"|"+v.Version)
	}

	var chosen []string
	err := huh.NewMultiSelect[string]().
		Title("Select packages to patch").
		Description("↑↓ navigate · Space toggle · Enter confirm · Ctrl+C cancel").
		Options(opts...).
		Value(&chosen).
		Run()

	if err != nil {
		return nil, err
	}

	// build lookup set
	chosenSet := make(map[string]bool, len(chosen))
	for _, k := range chosen {
		chosenSet[k] = true
	}

	var selected []audit.SafeVuln
	for _, v := range vulns {
		if chosenSet[v.PackageName+"|"+v.Version] {
			selected = append(selected, v)
		}
	}
	return selected, nil
}
