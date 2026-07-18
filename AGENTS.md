# AGENTS.md — Repo guide for LLM coding agents

> Read this first. It saves 20+ tool calls and ~15k tokens per conversation.

## What is Ansede?

Ansede is a **zero-dependency SAST (Static Application Security Testing) scanner** that finds security vulnerabilities in source code. It supports **Python, JavaScript/TypeScript, Go, Java, C#** with 35+ CWE types.

- **PyPI**: `ansede-static` (v6.4.0)
- **GitHub**: `mattybellx/Ansede`
- **License**: MIT
- **Unique strength**: Built-in IDOR/missing-authorization detection that Bandit, Semgrep OSS, and CodeQL miss.

## Repo structure (post-cleanup, July 2026)

```text
ansede-static-focus/
├── src/ansede_static/          # Main scanner source (Python)
│   ├── cli.py                  # CLI entry point, argument parsing
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
├── ansede_rust_core/           # Rust native parser core (tree-sitter based)
│   ├── src/                    # Rust source
│   └── python/                 # Python bindings
├── tests/                      # 1,183 unit tests (pytest)
├── rules/                      # YAML rule definitions
├── community_rules/            # Community-contributed rules
├── samples/                    # Test fixtures & vulnerable code samples
├── docker/                     # Docker build config
├── .github/                    # CI workflows
│   ├── workflows/
│   │   ├── ci.yml              # Main CI: test + lint
│   │   ├── build-release.yml   # Quality gates on push/PR
│   │   ├── release.yml         # Tagged release: compile binaries
│   │   ├── ansede-code-scanning.yml  # Self-demo: scan samples/ + tests/
│   │   ├── publish.yml         # PyPI publish (trusted publishing)
│   │   ├── scanner-image.yml   # Docker image build
│   │   ├── sbom.yml            # CycloneDX SBOM generation
│   │   └── sigstore-sign.yml   # Sigstore signing
│   └── scripts/
├── ansede.json                 # Default scanner config
├── .ansede/                    # Scanner internal data (cache.db, golden_corpus)
├── pyproject.toml              # Python package config (hatchling build)
├── CHANGELOG.md                # Full version history
├── README.md                   # Public-facing readme
├── SECURITY.md                 # Security policy
├── LICENSE                     # MIT
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

# Run a specific test file
pytest tests/test_python.py -q

# Run scanner on source
python -m ansede_static.cli src/ --format text

# Show scan stats
python -m ansede_static.cli --show-stats

# List all rules
python -m ansede_static.cli --list-rules
```

## Key architectural notes

1. **python_analyzer.py is the giant** — 8,500+ lines. It uses AST walking + taint tracking. Sink catalog is in `TAINT_SINKS` dict (~180 entries). Sanitizer catalog is in `SANITIZERS` dict.

2. **Rule detection is function-based** — `_rule_21(ctx)` for CWE-22, etc. These walk AST trees looking for specific patterns. Not regex-based.

3. **Licensing/counters** — `licensing.py` manages:
   - Daily scan counter: `~/.ansede/scan_count.json` (resets daily, with HMAC integrity)
   - Lifetime counter: `~/.ansede/lifetime_scan_count.json` (never resets)
   - Free tier check: `_check_scans_today()`
   - `bump_scan_count()` + `bump_lifetime_scan_count()` called from `cli.py`

4. **IFDS/taint** — Inter-procedural dataflow uses `GlobalGraph` in `ir/global_graph.py`. Cross-file analysis bridges Python↔JS.

5. **Rust core** — `ansede_rust_core/` provides fast native parsing via tree-sitter. Falls back to pure-Python if not compiled.

6. **Self-scan exclusion** — The `ansede-code-scanning.yml` workflow excludes `src/` and `ansede_rust_core/` because the scanner's own rule catalog strings (e.g., `"open"`, `"eval"`) would be false-positive matched against themselves.

## What was removed (July 2026 cleanup)

Everything not needed for the scanner CLI was deleted:

- `benchmarks/`, `tools/`, `scripts/`, `docs/`, `site/`, `webapp/`
- `intellij-plugin/`, `vscode-extension/`, `visualstudio-extension/`
- `campaign/`, `drafts/`, `reports/`, `assets/`, `tmp/`, `owasp-benchmark-java/`
- `render.yaml` (deployed the now-deleted webapp)
- All root-level JSON reports and MD roadmaps

## Common gotchas

- **Don't add imports from `benchmarks` or `tools`** — those directories don't exist anymore.
- **Test count**: 1,183 tests. If you see fewer, check for skipped platform-specific tests.
- **Pre-existing lint errors**: ~25 type-checker warnings in `cli.py` — all pre-existing, not from recent changes.
- **`id()`-based memoization**: `_get_taint_source` and `_get_sink_name` use `id(node)` as cache keys. This is sensitive to Python version memory allocator differences.
- **python_analyzer.py line references**: The CI `ansede-code-scanning.yml` used to flag the analyzer's own pattern strings as vulnerabilities. Now fixed by excluding `src/`.

## CI pipeline health

| Workflow | Trigger | What it does |
| --- | --- | --- |
| `ci.yml` | push/PR to main | pytest + ruff lint |
| `build-release.yml` | push/PR/tag | quality gates (tests + rule validation) |
| `release.yml` | tag `v*` | compile PyInstaller binaries + GitHub Release |
| `publish.yml` | tag `v*` | PyPI trusted publishing |
| `ansede-code-scanning.yml` | push/PR/schedule | Self-demo scan of samples/ + tests/ |
| `scanner-image.yml` | tag `v*` | Docker image to GHCR |
| `sbom.yml` | tag `v*` | CycloneDX SBOM |
| `sigstore-sign.yml` | workflow_call | Sigstore signing |
