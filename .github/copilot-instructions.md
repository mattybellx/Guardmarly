# Copilot Instructions — Guardmarly

Always read `AGENTS.md` first — it has the full repo map, commands, and architecture.

## Rules for this workspace

- Never import from `benchmarks`, `tools`, `scripts`, `webapp`, `campaign`, `docs`, or `site` — these were deleted July 2026.
- `python_analyzer.py` is 8,500+ lines; prefer grep_search before reading blind.
- `id()`-based memoization is used in `_get_taint_source` and `_get_sink_name` — sensitive to Python version.
- Self-scan CI excludes `src/` and `guardmarly_rust_core/` to avoid false positives on rule catalog strings.
- Lint errors in `cli.py` are all pre-existing (~25 type-checker warnings), not from recent changes.
- Run `pytest tests/ -q` after any change to verify nothing broke (1,183 tests, ~12s).

## Current Status

- 1,183 tests passing
- 5 languages: Python, JavaScript/TypeScript, Go, Java, C#
- 100% CVE recall (164/164)
- 35+ CWE types
- Incident clustering, symbolic guards, VLQ source maps, shadow detectors all active
- CI: 8 workflows (test+lint, quality gates, release, publish, self-scan, Docker, SBOM, Sigstore)