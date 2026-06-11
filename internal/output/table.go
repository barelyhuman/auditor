package output

import (
	"fmt"
	"os"
	"strings"

	"github.com/barelyhuman/auditor/internal/audit"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

var (
	critical = color.New(color.FgRed, color.Bold).SprintFunc()
	high     = color.New(color.FgRed).SprintFunc()
	moderate = color.New(color.FgYellow).SprintFunc()
	low      = color.New(color.FgCyan).SprintFunc()
)

func colorSeverity(sev string) string {
	switch sev {
	case "critical":
		return critical(sev)
	case "high":
		return high(sev)
	case "moderate":
		return moderate(sev)
	default:
		return low(sev)
	}
}

func RenderTable(vulns []audit.SafeVuln, noColor bool) {
	if noColor {
		color.NoColor = true
	}

	fmt.Printf("\nFound %d safe-fixable %s\n\n", len(vulns), plural(len(vulns), "vulnerability", "vulnerabilities"))

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Package", "Current", "Fix Version", "Severity", "CVE / Advisory"})
	table.SetBorder(false)
	table.SetColumnSeparator("  ")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeaderLine(true)
	table.SetAutoWrapText(false)

	for _, v := range vulns {
		advisory := v.AdvisoryURL
		if len(v.CVEIDs) > 0 {
			advisory = strings.Join(v.CVEIDs, ", ")
		}
		table.Append([]string{
			v.PackageName,
			v.Version,
			v.FixedVersion,
			colorSeverity(v.Severity),
			advisory,
		})
	}
	table.Render()
}

func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return singular
	}
	return pluralForm
}
