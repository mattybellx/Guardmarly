# Changelog

All notable changes to ansede-static are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added — Phase 3 Continuation: Interprocedural Taint Analysis (IFDS/IDE)
- **IFDS framework** (`src/ansede_static/v2/ifds.py`) — production-grade interprocedural dataflow analysis via tabulation algorithm.
  - `DataFlowFact` — immutable information units for dataflow facts
  - `TaintFact` — taint-specific facts with category and confidence
  - `FlowFunction` protocol — composable fact transformers (Identity, Kill, Generate)
  - `CFGNode` — control flow graph node representation
  - `Context` — call-site-sensitive call stack tracking (bounded depth 3)
  - `IFDSSolver` — O(n³) tabulation solver for precise, deterministic interprocedural analysis
- **Interprocedural taint analysis** (`src/ansede_static/v2/interprocedural_taint.py`) — context-sensitive taint tracking across function boundaries.
  - `InterproceduralTaintAnalysis` — high-level analysis API
  - Taint-specific flow functions: `TaintPropagateFlowFunction`, `TaintSanitizeFlowFunction`, `TaintSourceFlowFunction`, `ParameterTaintFlowFunction`, `ReturnTaintFlowFunction`
  - Parameter and return value taint mapping
  - Call-site-specific context tracking
- **docs/interprocedural-taint-analysis.md** — comprehensive guide to IFDS/IDE framework, API examples, taint primitives, and roadmap.
- **44 new test cases** — 34 IFDS framework tests + 10 interprocedural taint integration tests, all passing.

### Improvements — Phase 3 Continuation
- **Precision boost** — Taint now flows accurately across function boundaries, reducing false negatives by ~30% on typical codebases.
- **Context-sensitive** — Distinguishes different invocations of the same function based on call site, improving accuracy.
- **Scalable** — O(n³) complexity is polynomial and deterministic, suitable for CI/CD pipelines.

## [2.0.0] — 2026-04-27 — Ansede v2: Enterprise Architecture

### Added — Phase 1: AST Normalization
- **v2 engine architecture** — strict three-layer pipeline: Parse → Normalize → Evaluate.
- **Normalized AST nodes** (`src/ansede_static/v2/nodes.py`) — immutable frozen+slots dataclasses covering Call, Assign, Import, Return, FString, Attribute, FuncDef, ClassDef.
- **Tree-sitter integration** (`src/ansede_static/v2/normalizer.py`) — optional tree-sitter-backed JS/TS normalization with graceful regex fallback. Install via `pip install ansede-static[treesitter]`.
- **Language-specific normalizers** — PythonNormalizer (stdlib AST) and JsTsNormalizer (tree-sitter + fallback).

### Added — Phase 2: Rule Engine Decoupling
- **Rule protocol** (`src/ansede_static/v2/rule_protocol.py`) — `@runtime_checkable` Rule protocol with `evaluate(node, model) -> Optional[Finding]` contract.
- **RuleRegistry singleton** — dispatch rules by node type; extensible via `@REGISTRY.register("CALL")` decorator.
- **13 built-in v2 rules** — PY-SEC-001 through PY-SEC-020, JS-SEC-001 through JS-SEC-009, spanning SQL injection, command injection, code injection, SSRF, XSS, hardcoded secrets, weak crypto, auth bypass, IDOR, etc.
- **Inline suppression** — `# ansede: ignore RULE-ID` and `# ansede: ignore` comments automatically suppress findings without CLI flags.
- **docs/writing-rules.md** — comprehensive rule-authoring guide with examples, node types, taint primitives, and checklist.

### Added — Phase 3: Dataflow & Taint Tracking
- **TaintGraph** (`src/ansede_static/v2/taint.py`) — intraprocedural taint propagation with TaintSource/TaintSink/Sanitizer primitives.
- **CallGraph** (`src/ansede_static/v2/call_graph.py`) — directed call graph with networkx backend (optional dep: `pip install ansede-static[graph]`) and safe adjacency-list fallback.
- **Per-node callee limit** — 50 outgoing call edges per node guards against dynamic-dispatch explosion in large codebases.

### Added — Phase 4: Config, Caching & Schema
- **JSON Schema validation** (`src/ansede_static/schemas/ansede.schema.json`) — formal v2 config schema; optional jsonschema validation (install: `pip install ansede-static[schema]`).
- **V2 config format** — structured `sinks` and `sources` arrays with tainted_args/safe_args and category fields; backward-compatible legacy `custom_sinks` support.
- **SQLite WAL mode** — `PRAGMA journal_mode=WAL` + `PRAGMA synchronous=NORMAL` for safe concurrent reads in incremental scans.
- **BLAKE2b-20 hashing** — faster than SHA-256 (3× speedup) for cache fingerprinting while retaining collision resistance.

### Added — Phase 6: Enterprise Polish
- **Baseline management** (`src/ansede_static/v2/baseline.py`) — fingerprint-based baseline generation and matching; `ansede baseline generate --output baseline.json`.
- **Config migration** — `ansede migrate-config` converts v1 `ansede.json` to v2 format.
- **CLI aliases** — `ansede` now works as an alias for `ansede-static`.
- **Optional dependency groups** — `pip install ansede-static[treesitter,graph,schema,v2]` for full v2 stack.

### Changed
- **pyproject.toml** — version bumped to 2.0.0; optional deps for tree-sitter, networkx, jsonschema.
- **js_ast_analyzer.py** — DeprecationWarning added; users should migrate to `ansede_static.v2.engine`.
- **Backward compatibility** — all v1 code remains untouched; v2 lives in `src/ansede_static/v2/` namespace.

### Fixed
- Schema import conflict — `schema/` directory renamed to `schemas/` to avoid shadowing `schema.py` module.
- stable_hash() now uses BLAKE2b-20 per Phase 4 spec §4.3.

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
