# Copilot Instructions — Guardmarly

Always read `AGENTS.md` first — it has the full repo map, commands, and architecture.

## Rules for this workspace

- Never import from `benchmarks`, `tools`, `campaign`, or `site` — these were deleted July 2026. (`scripts/`, `docs/`, `webapp/` and `vscode-extension/` still exist.)
- `python_analyzer.py` is 8,500+ lines; prefer grep_search before reading blind.
- `id()`-based memoization is used in `_get_taint_source` and `_get_sink_name` — sensitive to Python version.
- Self-scan CI excludes `src/` and `guardmarly_rust_core/` to avoid false positives on rule catalog strings.
- Bump `src/guardmarly/_version.py` for releases; `pyproject.toml` is dynamic and `tests/test_version.py` guards drift.
- Run `pytest tests/ -q` after any change (1,310+ tests, ~12s), plus `ruff check` and `mkdocs build --strict` for docs changes.

## Current Status

- 1,310+ tests passing
- 7 full-AST languages: Python, JavaScript/TypeScript, Go, Java, C#, PHP, Ruby (+30 pattern-aware)
- 35+ CWE types
- Incident clustering, symbolic guards, VLQ source maps, shadow detectors all active
- CI: test matrix (Linux 3.9/3.12/3.13, Windows 3.13, macOS 3.12) + lint + wheel build; release, publish, self-scan, Docker, SBOM, Sigstore
- Open defect/backlog record: `IMPROVEMENTS.md`