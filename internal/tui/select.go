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
// nested is name|version → lockfile descendants; selecting a package hides those for this run.
func SelectPackages(vulns []audit.SafeVuln, nested map[string]map[string]bool) ([]audit.SafeVuln, error) {
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

	allOpts := optionsFor(sorted, nil, nested)
	var chosen []string
	err := huh.NewMultiSelect[string]().
		Title("Select packages to patch").
		Description("↑↓ navigate · Space toggle · Enter confirm · Ctrl+C cancel\nSelecting a package hides its transitives for this run").
		Options(allOpts...).
		OptionsFunc(func() []huh.Option[string] {
			return optionsFor(sorted, chosen, nested)
		}, &chosen).
		Value(&chosen).
		Run()

	if err != nil {
		return nil, err
	}

	chosen = dropNestedIDs(chosen, nested)
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

func optionsFor(sorted []audit.SafeVuln, chosen []string, nested map[string]map[string]bool) []huh.Option[string] {
	blocked := blockedIDs(chosen, nested)
	selected := make(map[string]bool, len(chosen))
	for _, id := range chosen {
		if !blocked[id] {
			selected[id] = true
		}
	}

	opts := make([]huh.Option[string], 0, len(sorted))
	seen := make(map[string]bool)
	for _, v := range sorted {
		id := v.PackageName + "|" + v.Version
		if seen[id] || blocked[id] {
			continue
		}
		seen[id] = true
		cves := ""
		if len(v.CVEIDs) > 0 {
			cves = "  " + v.CVEIDs[0]
		}
		label := fmt.Sprintf("%-8s  %-30s  %s → %s%s",
			v.Severity, v.PackageName, v.Version, v.FixedVersion, cves)
		opts = append(opts, huh.NewOption(label, id).Selected(selected[id]))
	}
	if len(opts) == 0 {
		return optionsFor(sorted, nil, nil) // ponytail: cycle select-all; show full list
	}
	return opts
}

func blockedIDs(selected []string, nested map[string]map[string]bool) map[string]bool {
	blocked := make(map[string]bool)
	for _, id := range selected {
		for child := range nested[id] {
			blocked[child] = true
		}
	}
	return blocked
}

func dropNestedIDs(selected []string, nested map[string]map[string]bool) []string {
	blocked := blockedIDs(selected, nested)
	out := make([]string, 0, len(selected))
	for _, id := range selected {
		if !blocked[id] {
			out = append(out, id)
		}
	}
	return out
}
