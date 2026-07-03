# GitHub Code Scanning — SARIF Integration Guide

**ansede-static** produces SARIF 2.1.0 output compatible with GitHub Code Scanning and any SARIF-capable CI platform. This guide explains how to upload results as GitHub Code Scanning alerts.

## Quick Start

```yaml
# .github/workflows/ansede-scan.yml
name: Ansede Security Scan
on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install ansede-static
        run: pip install ansede-static

      - name: Run ansede scan → SARIF
        run: |
          ansede-static . \
            --format sarif \
            --output results.sarif \
            --fail-on high \
            --verbose

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: ansede-static
```

That's it. After the workflow runs, findings appear under the **Security > Code Scanning** tab in your repository.

---

## Requirements

| Component | Minimum |
|---|---|
| ansede-static | v5.5.0+ |
| github/codeql-action | v3.x |
| SARIF format | `--format sarif` (default: text) |

## Advanced Configuration

### Failing the pipeline on severity thresholds

```yaml
      - name: Run ansede scan
        run: |
          ansede-static . \
            --format sarif \
            --output results.sarif \
            --fail-on critical   # exit code 1 if any critical finding
```

| `--fail-on` value | Behaviour |
|---|---|
| `critical` | Fail only on CRITICAL findings |
| `high` (default) | Fail on CRITICAL or HIGH |
| `medium` | Fail on CRITICAL, HIGH, or MEDIUM |
| `never` | Always exit 0 (advisory only) |

### Using a baseline to reduce noise

```yaml
      - name: Generate baseline (main branch only)
        if: github.ref == 'refs/heads/main'
        run: ansede-static . --format sarif --baseline-update --baseline .ansede-baseline.json

      - name: Scan with baseline (PRs)
        if: github.event_name == 'pull_request'
        run: |
          ansede-static . \
            --format sarif \
            --output results.sarif \
            --baseline .ansede-baseline.json
```

Only **new** findings (not in the baseline) are reported in the SARIF output and surfaced as Code Scanning alerts.

### Excluding third-party code

```yaml
      - name: Run ansede scan
        run: |
          ansede-static . \
            --format sarif \
            --output results.sarif \
            --exclude node_modules \
            --exclude vendor \
            --exclude __pycache__
```

### Limiting per-file analysis time

```yaml
      - name: Run ansede scan
        run: |
          ansede-static . \
            --format sarif \
            --output results.sarif \
            --timeout-per-file 60
```

Default is 30 seconds per file. Increase for large generated files, decrease for fast CI feedback.

---

## SARIF Output Structure

ansede-static SARIF output includes:

- **`runs[].tool`** — tool information (name `ansede-static`, version, semanticVersion)
- **`runs[].results[].ruleId`** — rule ID (e.g. `PY-001`, `JS-002`, `GO-78`)
- **`runs[].results[].level`** — `error` (critical/high), `warning` (medium), `note` (low/info)
- **`runs[].results[].message.text`** — human-readable finding title
- **`runs[].results[].locations`** — file path, line, column
- **`runs[].results[].codeFlows`** — source → sink data-flow traces (when traces exist)
- **`runs[].results[].partialFingerprints`** — stable hash for deduplication across scans
- **`runs[].results[].properties`** — includes `cwe`, `confidence`, `analysis_kind`, `severity`, `suggestion`
- **`runs[].results[].relatedLocations`** — related code context for the finding
- **`runs[].properties`** — summary counts (critical, high, medium, low, info)

### SARIF Example (simplified)

```json
{
  "version": "2.1.0",
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
  "runs": [{
    "tool": {
      "driver": {
        "name": "ansede-static",
        "version": "2.2.1",
        "semanticVersion": "2.2.1",
        "informationUri": "https://pypi.org/project/ansede-static/"
      }
    },
    "results": [{
      "ruleId": "JS-002",
      "level": "error",
      "message": { "text": "XSS via document.write()" },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {
            "uri": "src/app.ts",
            "uriBaseId": "%SRCROOT%"
          },
          "region": { "startLine": 15 }
        }
      }],
      "codeFlows": [{
        "threadFlows": [{
          "locations": [
            {
              "location": {
                "physicalLocation": {
                  "artifactLocation": { "uri": "src/app.ts", "uriBaseId": "%SRCROOT%" },
                  "region": { "startLine": 10 }
                },
                "message": { "text": "source `req.query.html`" }
              }
            },
            {
              "location": {
                "physicalLocation": {
                  "artifactLocation": { "uri": "src/app.ts", "uriBaseId": "%SRCROOT%" },
                  "region": { "startLine": 15 }
                },
                "message": { "text": "sink `document.write()`" }
              }
            }
          ]
        }]
      }],
      "partialFingerprints": {
        "primaryLocationLineHash": "a1b2c3d4e5..."
      },
      "properties": {
        "cwe": "CWE-79",
        "confidence": 0.96,
        "analysis_kind": "syntax-ast",
        "severity": "high",
        "suggestion": "Use DOMPurify.sanitize() or output encoding"
      }
    }],
    "properties": {
      "critical": 0,
      "high": 1,
      "medium": 0,
      "low": 0,
      "info": 0
    }
  }]
}
```

---

## Source Map Support

When scanning minified JavaScript bundles with associated source maps (`//# sourceMappingURL=`), ansede-static automatically remaps findings to the original source locations. SARIF output reflects this:

- **`artifactLocation.uri`** — points to the original source file (e.g. `src/app.ts`), not the bundle
- **`properties.originalFile`** — the source-mapped original file path (for reference)
- **Trace codeFlow locations** each resolve to their original source file per-frame

No configuration needed — place the `.map` file alongside the bundle.

---

## Tips

1. **Use `--verbose` in CI** to capture description and suggestion text in findings
2. **Pair with `--fail-on high`** to block PRs with real vulnerabilities while allowing medium/low through
3. **Combine with `--baseline`** after an initial full-scan on main to prevent alert fatigue
4. **Source-mapped JavaScript** works automatically — just ensure `.map` files are deployed
5. **Multiple languages** — ansede scans Python, JS/TS, Java, C#, Go, and Ruby in one pass

## Troubleshooting

| Problem | Solution |
|---|---|
| "No SARIF results uploaded" | Verify the SARIF file was created: `ls -la results.sarif` |
| Code Scanning shows 0 alerts | Check `--fail-on` threshold; alerts below the threshold are reported but don't fail |
| False positive in report | Add `# ansede: ignore[CWE-79]` to the line, or suppress via community rules |
| Baseline not reducing noise | Regenerate baseline on main branch: `ansede-static . --baseline-update` |
| Large SARIF file | Add `--exclude node_modules .venv` and increase `--timeout-per-file` |
