# auditor

A Go CLI tool that audits Node.js projects for CVEs and surgically patches them - without running npm.

## Install

```bash
go install github.com/barelyhuman/auditor@latest
```

Or build from source:

```bash
git clone https://github.com/barelyhuman/auditor
cd auditor
go build -o bin/auditor .
```

## Usage

```
auditor [path] [flags]

Flags:
      --dry-run            show what --fix would change without writing files
      --fix                interactively select and patch safe-fixable vulnerabilities
      --format string      output format [table|json|markdown] (default "table")
      --include-dev        include dev dependencies
      --legacy-peer-deps   use --legacy-peer-deps when running npm install after patching
      --no-color           disable color output
      --path string        path to Node.js project (default: current directory)
      --severity string    minimum severity to report [low|moderate|high|critical] (default "low")
```

### Audit

```bash
# Audit current directory
auditor

# Audit a specific project
auditor /path/to/project

# Only show high and critical
auditor --severity high

# Include dev dependencies
auditor --include-dev

# Output as JSON or Markdown
auditor --format json
auditor --format markdown
```

### Patch

```bash
# Interactive TUI: select which packages to patch
auditor --fix

# Preview changes without writing
auditor --fix --dry-run

# Workspace monorepo with peer dep conflicts
auditor --fix --legacy-peer-deps
```

The `--fix` flag opens an interactive checklist sorted by severity then alphabetically. Select packages with Space, confirm with Enter. After patching, run `npm install` (or `npm install --legacy-peer-deps`) to update `node_modules`.

## How it works

1. **Reads** `package-lock.json` directly - no npm subprocess needed
2. **Queries** OSV.dev `/v1/querybatch` with all installed packages
3. **Filters** to vulnerabilities where upgrading to the fix version does not cross a semver major boundary
4. **Displays** findings sorted by severity, with CVE IDs and advisory URLs
5. **Patches** (with `--fix`):
   - Finds the minimum published npm version that satisfies the CVE fix constraint
   - Updates `package-lock.json` entries: `version`, `resolved`, `integrity`
   - Updates `package.json` (root and all workspace members) for direct dependencies
   - Preserves key order and formatting via surgical byte-level edits ([sjson](https://github.com/tidwall/sjson))
   - Deduplicates: multiple CVEs for the same package are resolved to a single patch at the highest required version

## Workspace support

Works with npm workspace monorepos. Detects workspace members from the lockfile and updates each member's `package.json` when the dependency is declared there. Handles `dependencies`, `devDependencies`, `peerDependencies`, and `optionalDependencies`.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No safe-fixable vulnerabilities found |
| 1 | Safe-fixable vulnerabilities found (use `--fix` to patch) |
| 2 | Error (missing lockfile, network failure, etc.) |

## Requirements

- Go 1.23+
- A `package-lock.json` (npm v7+ format, lockfileVersion 2 or 3)
- Internet access to OSV.dev and registry.npmjs.org

npm does not need to be installed to audit. It is only needed to run `npm install` after patching to update `node_modules`.
