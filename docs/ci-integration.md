# CI integration

Guardmarly is designed to gate pull requests: scan, compare against the
findings you already accepted (a baseline), fail only on new ones, and publish
the results where reviewers already look.

## GitHub Action

```yaml
name: Security scan
on: [pull_request]

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  guardmarly:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mattybellx/Guardmarly@main
        with:
          path: .
          format: sarif
          output: guardmarly.sarif
          fail-on: high
          min-confidence: '0.65'
          upload-sarif: 'true'
          post-pr-comments: 'true'
```

### Action inputs

| Input | Default | Purpose |
| --- | --- | --- |
| `path` | `.` | File or directory to scan |
| `fail-on` | `high` | Severity that fails the job (`critical`…`info`, or `never`) |
| `format` | `sarif` | `text`, `json` or `sarif` |
| `output` | `guardmarly.sarif` | Report path (required for SARIF upload) |
| `exclude` | | Comma-separated path patterns to skip |
| `min-confidence` | `0.65` | Confidence floor for reported findings |
| `all-findings` | `false` | Ignore the confidence floor |
| `version` | | Pin a released version |
| `install-source` | `pypi` | `pypi`, `github` or `local` |
| `upload-sarif` | `true` | Upload to GitHub code scanning |
| `post-pr-comments` | `true` | Inline review comments for each finding |
| `output-dir` | | Write several formats in one pass |
| `noise-gate` | | Fail when findings/kLOC exceeds this ceiling |
| `license-key` | | Pro licence (optional; SARIF output is free) |

Outputs: `findings-count` (total findings across all files) and `sarif-file`
(path to the report that was written).

### Gating on new findings only

```yaml
      - name: Baseline scan
        run: guardmarly . --format json --output baseline.json --fail-on never

      - name: Scan (fails only on new findings)
        run: guardmarly . --baseline baseline.json --fail-on high
```

Commit `baseline.json` (regenerate deliberately, not on every PR) and the job
fails only when the branch adds something new. `--baseline-update` rewrites it
when you have reviewed and accepted the current set.

## SARIF / code scanning

Native SARIF output needs no post-processing:

```bash
guardmarly . --format sarif --output guardmarly.sarif --fail-on never
```

```yaml
      - uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: guardmarly.sarif
          category: guardmarly
```

Findings that carry a taint path emit SARIF `codeFlows`, which code scanning
renders as a step-by-step trace. Findings without one (pattern rules) appear as
single-location results.

Keep the report out of `guardmarly.json`: that filename is the scanner's
configuration file.

## Other CI systems

Any runner works if Python is available:

```bash
pip install guardmarly
guardmarly . --format json --output guardmarly-report.json --fail-on high
```

The exit codes are the contract — `0` clean, `1` new findings, `2` usage or
degraded analysis, `5` missing licence for a Pro feature. See
[Getting started](getting-started.md#exit-codes).

## Keeping CI fast

```bash
guardmarly . --batch --workers 4           # parallel, shared analysis graph
guardmarly . --incremental                 # git-diff mode (PR builds)
guardmarly . --exclude vendor --exclude node_modules --exclude .venv
```

For monorepos, `--incremental` plus an exclusion list for vendored code
typically dominates any other optimisation.

## A note on self-scanning

This repository's own workflow
([`.github/workflows/guardmarly-code-scanning.yml`](https://github.com/mattybellx/Guardmarly/blob/main/.github/workflows/guardmarly-code-scanning.yml))
scans the codebase on every push and weekly. It excludes `src/` and
`guardmarly_rust_core/` because the rule catalogue itself contains the pattern
strings the scanner looks for — the scanner would otherwise report its own
detector definitions as vulnerabilities. Projects that vendor similar rule
catalogues need the same exclusion.
