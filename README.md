# auditor

**Fix the CVEs you can actually fix.**

auditor reads your `package-lock.json`, queries [OSV.dev](https://osv.dev) for vulnerabilities, and shows only patches that stay within the same **semver major**—then applies them with **surgical** lockfile edits, no npm subprocess required.

```bash
go install github.com/barelyhuman/auditor@latest
```

## The problem with npm audit

`npm audit` is the default security check for Node.js projects, but the workflow it encourages often creates more work than it resolves.

| Pain | What happens | Why it hurts |
|------|--------------|--------------|
| **Noise** | `npm audit` lists every advisory, including transitive deps with no semver-safe fix | Teams ignore output or chase unfixable issues |
| **Risky fixes** | `npm audit fix` (especially `--force`) can cross major versions and break peer deps | "Security fix" PRs become surprise breakages |
| **Heavy tooling** | Audit runs through npm/Node | Slow in CI, fails in environments without npm |
| **Messy diffs** | npm rewrites `package-lock.json` wholesale | Review fatigue; merge conflicts in monorepos |
| **Unclear actionability** | Hard to answer "what can we ship today?" | Security tickets stall |

```text
$ npm audit
47 vulnerabilities (6 low, 12 moderate, 21 high, 8 critical)
  ↑ most require major bumps or have no fix path

$ auditor
Found 3 safe-fixable vulnerabilities
  ↑ same major, patchable today
```

## Why auditor

- **Actionable only** — filters to **safe-fixable** CVEs: upgrades that do not cross a semver major boundary. No `--force` roulette.
- **Fast and standalone** — reads `package-lock.json` directly; no npm subprocess needed to audit.
- **Surgical patches** — updates `version`, `resolved`, and `integrity` via [sjson](https://github.com/tidwall/sjson), preserving key order and formatting.
- **Interactive patching** — `--fix` opens a TUI checklist so you pick exactly which packages to patch.
- **Workspace-aware** — detects npm workspace members and updates each member's `package.json` when needed.

## npm audit vs auditor

| | `npm audit` | `auditor` |
|---|-------------|-----------|
| Runs without npm | No | Yes (audit only) |
| Shows unfixable CVEs | Yes | No |
| Allows major bumps on fix | Yes (`--force`) | Never |
| Lockfile edit style | Full rewrite | Surgical byte edits |
| Vuln source | npm advisory DB | OSV.dev |
| Interactive patch picker | No | Yes (`--fix`) |

## Try it in 30 seconds

```bash
go install github.com/barelyhuman/auditor@latest
auditor                  # audit
auditor --fix --dry-run  # preview patches
```

See [Usage](#usage) below for all flags and options.

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

Under the hood:

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
