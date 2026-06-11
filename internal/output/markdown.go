package output

import (
	"fmt"
	"strings"

	"github.com/barelyhuman/auditor/internal/audit"
)

func RenderMarkdown(vulns []audit.SafeVuln) {
	fmt.Printf("## Audit Report — %d safe-fixable %s\n\n", len(vulns), plural(len(vulns), "vulnerability", "vulnerabilities"))
	fmt.Println("| Package | Current | Fix Version | Severity | CVE / Advisory |")
	fmt.Println("|---------|---------|-------------|----------|----------------|")
	for _, v := range vulns {
		advisory := v.AdvisoryURL
		if len(v.CVEIDs) > 0 {
			advisory = strings.Join(v.CVEIDs, ", ")
		}
		fmt.Printf("| %s | %s | %s | %s | %s |\n",
			v.PackageName, v.Version, v.FixedVersion, v.Severity, advisory)
	}
}
