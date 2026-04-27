# Changelog

All notable changes to ansede-static are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- `AnsedeConfig` is now usable directly from the Python API via `scan_file(..., config=...)` and `scan_code(..., config=...)`.
- JSON report envelopes now include a top-level `fingerprint_version` marker to document the baseline fingerprint format.
- VS Code extension now supports debounced `scanOnType` scanning and a configurable `ansede.scanTimeoutMs` setting.
- Rule contracts are now exposed through a new `src/ansede_static/rules.py` catalog and surfaced in JSON/SARIF finding payloads.
- New CLI catalog commands: `--list-rules`, `--describe-rule`, and `--list-js-backends`.
- A new trust-oriented quality harness is available via `python -m benchmarks.quality_benchmark`.
- A new manifest-driven external corpus runner is available via `python -m benchmarks.external_corpus --manifest benchmarks/external_manifest.json`.
- The external corpus runner now supports pinned git-backed manifest entries with local caching plus `--cache-dir`, `--refresh`, and `--offline` controls for larger real-world corpus workflows.
- A curated opt-in real-world manifest is now shipped in `benchmarks/real_world_manifest.json`, initially covering pinned NodeGoat route files for open redirect, brute-force, cookie-flag, and eval-style code execution checks.
- A new performance smoke benchmark is available via `python -m benchmarks.perf_benchmark`.
- A roadmap document now tracks concrete v1.3 / v1.4 / v2.0 milestone tickets in `ROADMAP.md`.
- The experimental JS/TS AST path now includes a zero-dependency structural call/property parser and shared `js_engine` helpers for syntax-aware detections before fallback merging.
- The structural JS/TS engine now detects React / JSX `dangerouslySetInnerHTML` flows and object-literal route/auth patterns such as Fastify-style `route({...})` definitions and options-object hooks.
- The JS engine now resolves relative-import helper functions and local helper call chains for redirect, SSRF, path traversal, and route access-control findings.
- Route/auth heuristics now understand nested route option semantics such as Hapi-style `options.auth` / `scope` and helper-based auth / privilege checks.
- Helper summaries now propagate return-value taint across local and imported JS/TS call chains, allowing sink checks to catch values returned through nested helper layers before later redirect / SSRF / path operations.
- Route/auth heuristics now understand broader framework semantics including Koa-style `router.use(...)` auth prefixes, NestJS decorator routes/guards, and Next.js file-based route handlers with dynamic `params` segments.
- JS project indexing now uses a workspace-wide module graph cache so repeated route and taint analysis can reuse parsed file indexes across larger repositories.

### Changed
- `disable_rules` from `ansede.json` are now enforced using either stable detector IDs (for example `PY-020`) or whole-CWE tokens (for example `CWE-862`).
- `custom_sinks` now use an explicit object schema (`cwe`, `title`, `severity`) instead of the ambiguous legacy list format.
- `--ai-triage` help text now describes the implemented offline heuristic triage behavior rather than implying an external LLM requirement.
- JS/TS scans now use an explicit backend-selection contract (`auto`, `classic`, `structural`) in the CLI and Python API.
- Report envelopes now record requested and selected JS backend execution metadata.
- CI is now intended to cover cross-platform smoke runs plus quality/performance benchmark visibility alongside unit tests.
- `--experimental-js-ast` now routes scans through a syntax-aware structural engine before merging fallback coverage from the standard JS analyzer.
- `--apply-fixes` now only auto-applies safe inline edits; multi-line or ambiguous fixes remain suggestions for manual review.
- VS Code extension workspace scans now cover Python, JavaScript, JSX, TypeScript, and TSX files.
- VS Code quick fixes now register for the full supported JS/TS editor surface instead of plain JavaScript only.
- `js_analyzer.py` is now a thin orchestrator over shared `js_engine` modules instead of a single monolithic implementation file.

### Fixed
- VS Code extension now auto-detects `ansede-static` in common workspace virtualenv locations before falling back to `PATH`.
- Missing `ansede-static` executable errors in the VS Code extension are now surfaced with a targeted setup message.
- CLI starter config written by `--init` now matches the implemented `custom_sinks` schema.

## [1.2.0] — 2026-04-24

### Added
- **Inline suppression** — `# ansede: ignore` or `# ansede: ignore[CWE-862]` on any line to suppress findings. Works in both Python (`#`) and JavaScript (`//`) comments.
- **`--baseline` flag** — pass a previous JSON report to only show *new* findings. Ideal for CI diff-scanning on PRs.
- **`--init` flag** — write a starter `ansede.json` config to the project root.
- **`--incremental` flag** — scan only files changed in `git diff HEAD`; useful for pre-commit hooks on large monorepos.
- **`--apply-fixes` flag** — interactively apply auto-fixes to source files.
- **`--ai-triage` flag** — offline heuristic triage pass; suppresses findings in test/mock/fixture contexts.
- **CWE-862 body-mutation analysis** — the missing-auth rule now inspects function bodies for state-mutating calls (db.commit, .save, .delete, etc.) to distinguish risky unprotected routes from harmless read-only endpoints.
- New public-route patterns: `/index`, `/home`, `/about`, `/terms`, `/privacy`, `/api/docs`, `/swagger`, `/healthz`, `/readiness`, and more.
- Resource-ID detection in route paths (`<int:id>`, `<uuid:pk>`) — these routes are flagged HIGH even on GET since they access specific resources.
- Community files: CONTRIBUTING.md, SECURITY.md, issue templates.
- Versioned JSON report envelopes with aggregate summaries.
- Intermediate finding IR scaffolding and a zero-dependency SQLite cache module.
- VS Code extension protocol/runner helpers plus extension build validation in CI.
- JavaScript route-level **CWE-639 IDOR** and **CWE-285 missing ownership** heuristics for Express/Router handlers using resource IDs without owner scoping.
- Trace-aware evidence for JS access-control findings, including route, resource parameter, auth middleware, missing guard, and sink steps.
- JavaScript route-aware **CWE-862 missing authentication**, **CWE-285 broken admin access control**, and **CWE-287 auth bypass via presence-only credential checks** heuristics.
- Three new synthetic JS benchmark cases covering missing auth, broken admin access control, and presence-only auth bypass.
- New synthetic Python benchmark case covering an admin route protected only by authentication with no privilege check.
- Finding metadata now carries `analysis_kind` through JSON/SARIF/IR/VS Code surfaces so downstream tooling can distinguish direct patterns from heuristic route or taint findings.
- Findings now carry stable analyzer-specific `rule_id` values (for example `PY-024`, `JS-034`) through JSON, SARIF, IR, CLI baseline matching, and VS Code diagnostics.
- **CWE-307** (no rate limiting on auth routes) and **CWE-352** (missing CSRF protection) JS rules and tests.
- `tests/test_config.py` — 12-case regression suite covering `exclude_paths` field name, invalid JSON, malformed sinks, and `None` workspace fallback.
- Expanded `tests/test_cache.py` — overwrite, bucket isolation, missing key, context-manager, and `stable_hash` determinism tests.
- Offline CWE explanation library expanded to cover all 27+ detected categories.
- SQLite cache `evict_older_than(bucket, days)` method for bounded cache growth.

### Changed
- **`rich` is now an optional dependency** — `pip install ansede-static` is truly zero-dependency; install `pip install "ansede-static[rich]"` for colored terminal output.
- **CWE-862 false-positive reduction** — pure GET routes with no state mutation and no resource IDs in the path are no longer flagged.
- JSON examples and downstream integrations now use the top-level report envelope (`results`, `summary`, `schema_version`) instead of assuming a raw array.
- README capability framing now documents current JS/Python scope, synthetic benchmark limits, and the expanded benchmark corpus.
- Python admin access-control detection now recognises explicit inline privilege guards, reducing false positives while preserving auth-only admin route detection.
- Route- and taint-derived findings now emit calibrated confidence scores.
- SARIF rule emission no longer collapses distinct findings under plain CWE IDs when the analyzer has a more specific stable detector ID.
- GitHub Action consolidated from three scans to one primary scan plus optional count derivation from existing output.
- README "Additional CLI flags" table added with stability levels for experimental flags.

### Fixed
- `config.py`: field name mismatch (`exclude` → `exclude_paths`) that silently discarded all path exclusions from `ansede.json`.
- `config.py`: bare `except Exception: pass` replaced with `logging.warning()` so config parse errors surface instead of vanishing.
- GitHub Action finding counts now parse the JSON envelope correctly.
- VS Code extension scans now stream document contents over stdin instead of assuming child-process input wiring.
- `action.yml` author field corrected to `mattybellx`.

- **CWE-862 body-mutation analysis** — the missing-auth rule now inspects function bodies for state-mutating calls (db.commit, .save, .delete, etc.) to distinguish truly risky unprotected routes from harmless read-only endpoints.
- New public-route patterns: `/index`, `/home`, `/about`, `/terms`, `/privacy`, `/api/docs`, `/swagger`, `/healthz`, `/readiness`, and more.
- Resource-ID detection in route paths (`<int:id>`, `<uuid:pk>`) — these routes are flagged HIGH even on GET since they access specific resources.
- Community files: CONTRIBUTING.md, SECURITY.md, issue templates.
- Versioned JSON report envelopes with aggregate summaries.
- Intermediate finding IR scaffolding and a zero-dependency SQLite cache module.
- VS Code extension protocol/runner helpers plus extension build validation in CI.
- JavaScript route-level **CWE-639 IDOR** and **CWE-285 missing ownership** heuristics for Express/Router handlers using resource IDs without owner scoping.
- Trace-aware evidence for JS access-control findings, including route, resource parameter, auth middleware, missing guard, and sink steps.
- JavaScript route-aware **CWE-862 missing authentication**, **CWE-285 broken admin access control**, and **CWE-287 auth bypass via presence-only credential checks** heuristics.
- Three new synthetic JS benchmark cases covering missing auth, broken admin access control, and presence-only auth bypass.
- New synthetic Python benchmark case covering an admin route protected only by authentication with no privilege check.
- Finding metadata now carries `analysis_kind` through JSON/SARIF/IR/VS Code surfaces so downstream tooling can distinguish direct patterns from heuristic route or taint findings.
- Findings now carry stable analyzer-specific `rule_id` values (for example `PY-024`, `JS-034`) through JSON, SARIF, IR, CLI baseline matching, and VS Code diagnostics.

### Changed
- **CWE-862 false-positive reduction** — pure GET routes with no state mutation and no resource IDs in the path are no longer flagged. POST/PUT/DELETE routes and routes with resource IDs are still flagged as HIGH. Admin routes remain CRITICAL.
- JSON examples and downstream integrations now use the top-level report envelope (`results`, `summary`, `schema_version`) instead of assuming a raw array.
- README capability framing now documents current JS/Python scope, synthetic benchmark limits, and the expanded 26-case benchmark corpus.
- Python admin access-control detection now recognizes explicit inline privilege guards such as `if not current_user.is_admin: abort(403)`, role comparisons, and helper calls like `require_admin(...)`, reducing false positives while preserving auth-only admin route detection.
- Route- and taint-derived findings now emit calibrated confidence scores and expose their provenance in verbose text, JSON, SARIF, and VS Code diagnostics.
- SARIF rule emission no longer collapses distinct findings under plain CWE IDs when the analyzer has a more specific stable detector ID.

### Fixed
- GitHub Action finding counts now parse the JSON envelope correctly.
- VS Code extension scans now stream document contents over stdin instead of assuming child-process input wiring that never happened.

## [1.1.0] — 2025-01-20

### Added
- 20 modular rule functions (`_rule_01` through `_rule_20`) replacing the monolithic `_detect()` function.
- `_Ctx` dataclass for shared analysis context.
- Pre-commit hook configuration (`.pre-commit-hooks.yaml`).
- GitHub Actions composite action (`action.yml`).
- CI workflow testing Python 3.9–3.13.
- Benchmarks and synthetic CVE-pattern corpus under `benchmarks/`.

### Changed
- `_detect()` cyclomatic complexity reduced from 308 to ~15.

### Fixed
- `except Exception: pass` in js_analyzer.py now logs with `_log.debug()`.
- Benchmark Unicode encoding on Windows (UTF-8 reconfigure).
- `_ownership_re` shared-scope leak and `ctx` variable shadowing in rule functions.

## [1.0.0] — 2025-01-08

Initial release.

- 20 Python security rules (CWE-89, CWE-78, CWE-502, CWE-22, CWE-798, CWE-327, CWE-338, CWE-862, CWE-639, CWE-285, CWE-117, CWE-918, and more).
- 14 JavaScript/TypeScript rules (CWE-79, CWE-95, CWE-78, CWE-89, CWE-798, CWE-22, CWE-601, CWE-918, CWE-1321, CWE-1004, CWE-942, CWE-209, CWE-338, CWE-400).
- Output formats: text, JSON, SARIF 2.1.0.
- Zero runtime dependencies — pure stdlib.
- Auto-fix suggestions for every finding.
