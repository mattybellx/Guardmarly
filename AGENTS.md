# AGENTS.md — Repo guide for LLM coding agents

> Read this first. It saves 20+ tool calls and ~15k tokens per conversation.

## What is Guardmarly?

Guardmarly is a **SAST (Static Application Security Testing) scanner** that finds security vulnerabilities in source code, with a focus on authorization gaps (IDOR/CWE-639). It supports **Python, JavaScript/TypeScript, Go, Java, C#** plus 35+ pattern-aware languages with 35+ CWE types.

- **PyPI**: `guardmarly` (v6.4.0)
- **GitHub**: `mattybellx/Guardmarly`
- **License**: See LICENSE file (custom terms)
- **Unique strength**: Built-in IDOR/missing-authorization detection that Bandit, Semgrep OSS, and CodeQL miss.

## Repo structure (verified 2026-09-10)

> The July 2026 "strip to core scanner essentials" pass removed the docs site
> content, marketing material and IDE-plugin directories. `docs/`, `scripts/`,
> `webapp/` and `vscode-extension/` were **kept** — do not assume they are gone.

```text
guardmarly-focus/
├── src/guardmarly/          # Main scanner source (Python)
│   ├── cli.py                  # CLI entry point, argument parsing
│   ├── _version.py             # Single source of truth for the version
│   ├── _stdio.py               # Console-encoding hardening for entry points
│   ├── suppressions.py         # `# guardmarly: ignore[...]` enforcement
│   ├── python_analyzer.py      # Python AST security analyzer (~8500 lines)
│   ├── java_analyzer.py        # Java analyzer
│   ├── js_analyzer.py          # JS/TS analyzer
│   ├── js_ast_analyzer.py      # JS structural AST analyzer
│   ├── js_engine/              # JS engine subpackage
│   ├── csharp_analyzer.py      # C# analyzer
│   ├── go_engine/              # Go analysis engine
│   ├── licensing.py            # License validation, scan counters, Stripe
│   ├── reporters.py            # Output formatters (text, JSON, SARIF, HTML)
│   ├── rules.py                # Rule catalog & descriptions
│   ├── engine/                 # Core analysis engine
│   ├── frameworks/             # Framework-specific knowledge
│   ├── graph/                  # Graph-based analysis structures
│   ├── ir/                     # Intermediate representation (GlobalGraph)
│   ├── ssa_taint.py            # SSA-lite taint analysis
│   ├── hardening.py            # Hardening checks
│   └── _types.py               # Core types (Finding, Severity, AnalysisResult)
├── guardmarly_rust_core/           # Rust native parser core (tree-sitter based)
│   ├── src/                    # Rust source
│   └── python/                 # Python bindings
├── tests/                      # 1,310+ unit tests (pytest)
├── rules/                      # YAML rule definitions + rules/specs/ framework specs
├── community_rules/            # Community-contributed rules
├── samples/                    # Test fixtures & vulnerable code samples
├── docs/                       # MkDocs source (site built by .github/workflows/pages.yml)
├── scripts/                    # Benchmark + corpus harness (fetch_corpora, benchmark, perf_check)
├── webapp/                     # guardmarly.onrender.com landing page + demo scanner
├── vscode-extension/           # VS Code extension (Marketplace, v1.6.x)
├── docker/                     # Docker build config
├── IMPROVEMENTS.md             # Defect history + prioritised backlog
├── .github/                    # CI workflows
│   ├── workflows/
│   │   ├── ci.yml              # Main CI: test + lint
│   │   ├── build-release.yml   # Quality gates on push/PR
│   │   ├── release.yml         # Tagged release: compile binaries
│   │   ├── guardmarly-code-scanning.yml  # Self-demo: scan samples/ + tests/
│   │   ├── publish.yml         # PyPI publish (trusted publishing)
│   │   ├── scanner-image.yml   # Docker image build
│   │   ├── sbom.yml            # CycloneDX SBOM generation
│   │   └── sigstore-sign.yml   # Sigstore signing
│   └── scripts/
├── guardmarly.json                 # Default scanner config
├── .guardmarly/                    # Scanner internal data (cache.db, golden_corpus)
├── pyproject.toml              # Python package config (hatchling build)
├── CHANGELOG.md                # Full version history
├── README.md                   # Public-facing readme
├── SECURITY.md                 # Security policy
├── LICENSE                     # Custom license
├── Dockerfile                  # Container build
├── action.yml                  # GitHub Action entry point
└── ci-workflow.example.yml     # Example CI config for users
```

## Build, test, run

```bash
# Install dev deps
pip install -e ".[dev]"

# Run ALL tests (~12s on warm cache)
pytest tests/ -q

# Lint (configuration lives in pyproject.toml [tool.ruff])
ruff check

# Docs site (strict: fails on broken nav/links)
pip install -r requirements-docs.txt && mkdocs build --strict

# Run a specific test file
pytest tests/test_python.py -q

# Run scanner on source
python -m guardmarly.cli src/ --format text

# Show scan stats
python -m guardmarly.cli --show-stats

# List all rules
python -m guardmarly.cli --list-rules
```

## Key architectural notes

1. **python_analyzer.py is the giant** — 8,500+ lines. It uses AST walking + taint tracking. Sink catalog is in `TAINT_SINKS` dict (~180 entries). Sanitizer catalog is in `SANITIZERS` dict.

2. **Rule detection is function-based** — `_rule_21(ctx)` for CWE-22, etc. These walk AST trees looking for specific patterns. Not regex-based.

3. **Licensing/counters** — `licensing.py` manages:
   - Daily scan counter: `~/.guardmarly/scan_count.json` (resets daily, with HMAC integrity)
   - Lifetime counter: `~/.guardmarly/lifetime_scan_count.json` (never resets)
   - Free tier check: `_check_scans_today()`
   - `bump_scan_count()` + `bump_lifetime_scan_count()` called from `cli.py`

4. **IFDS/taint** — Inter-procedural dataflow uses `GlobalGraph` in `ir/global_graph.py`. Cross-file analysis bridges Python↔JS.

5. **Rust core** — `guardmarly_rust_core/` provides fast native parsing via tree-sitter. Falls back to pure-Python if not compiled.

6. **Self-scan exclusion** — The `guardmarly-code-scanning.yml` workflow excludes `src/` and `guardmarly_rust_core/` because the scanner's own rule catalog strings (e.g., `"open"`, `"eval"`) would be false-positive matched against themselves.

## What was removed (July 2026 cleanup)

Everything not needed for the scanner CLI was deleted:

- `benchmarks/`, `tools/`, `scripts/`, `docs/`, `site/`, `webapp/`
- `intellij-plugin/`, `vscode-extension/`, `visualstudio-extension/`
- `campaign/`, `drafts/`, `reports/`, `assets/`, `tmp/`, `owasp-benchmark-java/`
- `render.yaml` (deployed the now-deleted webapp)
- All root-level JSON reports and MD roadmaps

## Common gotchas

- **Don't add imports from `benchmarks` or `tools`** — those directories don't exist anymore.
- **Test count**: 1,310+ tests. Run `pytest tests/ -q` for the current count. If you see fewer, check for skipped platform-specific tests.
- **Version**: bump `src/guardmarly/_version.py` only — `pyproject.toml` reads it
  dynamically and `tests/test_version.py` fails on drift.
- **Console encoding**: anything a user-facing entry point prints must survive a
  non-UTF-8 console (`test_cli.py::test_cli_writes_report_under_non_utf8_console`).
- **`guardmarly.json` is the config filename**, not a report filename — writing
  scan output there makes the next run warn and ignore it.
- **`id()`-based memoization**: `_get_taint_source` and `_get_sink_name` use `id(node)` as cache keys. This is sensitive to Python version memory allocator differences.
- **python_analyzer.py line references**: The CI `guardmarly-code-scanning.yml` excludes `src/` and `guardmarly_rust_core/` because the rule catalogue's own pattern strings would match themselves.

## CI pipeline health

| Workflow | Trigger | What it does |
| --- | --- | --- |
| `ci.yml` | push/PR to main | pytest + ruff lint |
| `build-release.yml` | push/PR/tag | quality gates (tests + rule validation) |
| `release.yml` | tag `v*` | compile PyInstaller binaries + GitHub Release |
| `publish.yml` | tag `v*` | PyPI trusted publishing |
| `guardmarly-code-scanning.yml` | push/PR/schedule | Self-demo scan of samples/ + tests/ |
| `scanner-image.yml` | tag `v*` | Docker image to GHCR |
| `sbom.yml` | tag `v*` | CycloneDX SBOM |
| `sigstore-sign.yml` | workflow_call | Sigstore signing |
