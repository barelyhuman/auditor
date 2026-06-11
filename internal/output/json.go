package output

import (
	"encoding/json"
	"fmt"

	"github.com/barelyhuman/auditor/internal/audit"
)

func RenderJSON(vulns []audit.SafeVuln) {
	data, _ := json.MarshalIndent(vulns, "", "  ")
	fmt.Println(string(data))
}
