package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/barelyhuman/auditor/internal/audit"
	"github.com/barelyhuman/auditor/internal/lockfile"
	"github.com/barelyhuman/auditor/internal/osv"
	"github.com/barelyhuman/auditor/internal/output"
	"github.com/spf13/cobra"
)

var (
	flagSeverity   string
	flagFormat     string
	flagPath       string
	flagIncludeDev bool
	flagNoColor    bool
)

var rootCmd = &cobra.Command{
	Use:   "auditor [path]",
	Short: "Audit Node.js dependencies for safe-fixable CVEs",
	Long: `auditor reads package-lock.json, queries OSV.dev for vulnerabilities,
and reports only those fixable without breaking semver changes.`,
	Args:          cobra.MaximumNArgs(1),
	RunE:          run,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(2)
	}
}

func init() {
	rootCmd.Flags().StringVar(&flagSeverity, "severity", "low", "minimum severity to report [low|moderate|high|critical]")
	rootCmd.Flags().StringVar(&flagFormat, "format", "table", "output format [table|json|markdown]")
	rootCmd.Flags().StringVar(&flagPath, "path", "", "path to Node.js project (default: current directory)")
	rootCmd.Flags().BoolVar(&flagIncludeDev, "include-dev", false, "include dev dependencies")
	rootCmd.Flags().BoolVar(&flagNoColor, "no-color", false, "disable color output")
}

func run(cmd *cobra.Command, args []string) error {
	projectDir := resolveDir(args)

	if err := validateProject(projectDir); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Reading lockfile from %s...\n", projectDir)
	packages, err := lockfile.ReadPackages(projectDir)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Found %d packages. Querying OSV.dev...\n", len(packages))

	vulnMap, err := osv.QueryPackages(packages)
	if err != nil {
		return fmt.Errorf("OSV query failed: %w", err)
	}

	vulns := audit.FilterSafeFixes(packages, vulnMap, flagSeverity, flagIncludeDev)

	if len(vulns) == 0 {
		fmt.Println("No safe-fixable vulnerabilities found.")
		os.Exit(0)
	}

	switch flagFormat {
	case "json":
		output.RenderJSON(vulns)
	case "markdown":
		output.RenderMarkdown(vulns)
	default:
		output.RenderTable(vulns, flagNoColor)
	}

	os.Exit(1)
	return nil
}

func resolveDir(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	if flagPath != "" {
		return flagPath
	}
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	return dir
}

func validateProject(dir string) error {
	if _, err := os.Stat(filepath.Join(dir, "package.json")); os.IsNotExist(err) {
		return fmt.Errorf("package.json not found in %s — not a Node.js project", dir)
	}
	return nil
}
