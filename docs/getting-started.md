# Getting Started

## Install

```bash
pip install ansede-static
```

Or install with extras for development:

```bash
pip install "ansede-static[dev]"   # pytest, mypy, ruff
pip install ansede-static              # standard install (includes rich terminal output)
pip install "ansede-static[graph]"  # networkx for cross-language graphs
```

## Quick start

```bash
# Scan a directory (default: text output)
ansede-static src/

# JSON output for machine processing
ansede-static src/ --format json --output findings.json

# SARIF for GitHub Code Scanning
ansede-static src/ --format sarif --output results.sarif

# HTML dashboard (interactive report)
ansede-static src/ --format html --output report.html
```

## Batch mode (fastest for large projects)

```bash
# Shared cache + parallel workers
ansede-static src/ --batch --workers 8
```

## CI mode

```bash
# Gate CI on high+ severity findings
ansede-static src/ --fail-on high
```

## Useful modes

| Flag | Purpose |
|------|---------|
| `--batch` | Shared GlobalGraph + parallel workers (5x faster) |
| `--incremental` | Scan only files changed in git diff |
| `--diff-only` | Report only findings intersecting git diff hunks |
| `--baseline FILE` | Compare against a baseline JSON; only new findings |
| `--cross-language` | Detect taint paths across backend/frontend |
| `--format sarif` | GitHub Code Scanning integration |
| `--format html` | Interactive browser dashboard |
| `--fail-on high` | Exit code 1 if any HIGH+ finding |
| `--audit` | Classify findings as TP/FP/NeedsReview |
| `--entropy` | Enable entropy-based secret detection |
| `--watch` | Watch files for changes and re-scan automatically |

## OpenAPI/Swagger route bridge

```bash
# Auto-discover OpenAPI specs and match routes to backend handlers
ansede-static . --openapi-report
```

Reports spec routes that are (and aren't) matched by backend route handlers, enabling cross-language taint tracking.

## IDE integration

```bash
# Start LSP server for IDE integration
ansede-static --lsp
```
