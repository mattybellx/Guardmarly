# Architecture

Guardmarly is a pipeline of small, replaceable stages. Nothing in the analysis
core requires a network call, a daemon, or a third-party parser.

```text
 files ──► language detection ──► per-language analysis ──┐
                                                          │
                    ┌─────────────────────────────────────┤
                    │                                     │
             route/framework specs                  taint engine
             (rules/specs/*.yaml)               (SSA-lite + call graph)
                    │                                     │
                    └──────────────► findings ◄───────────┘
                                       │
                     triage → confidence → clustering → baseline
                                       │
                       reporters (text │ json │ sarif │ html │ ciso)
```

## Stage by stage

### 1. Collection and language detection

`src/guardmarly/__init__.py` maps file extensions to analysers and owns the
`scan_file` / `scan_files` / `scan_code` entry points. Collection honours
`.gitignore`-style exclusions, `.guardmarlyignore`, and built-in skips
(`node_modules/`, `.venv/`, minified bundles, generated files).

### 2. Per-language analysis

| Module | Role |
| --- | --- |
| `python_analyzer.py` | Python AST walk, taint sources/sinks/sanitizers, framework routes |
| `js_analyzer.py`, `js_ast_analyzer.py`, `js_engine/` | JavaScript/TypeScript, with classic / structural / Pratt backends |
| `java_analyzer.py`, `java_ast_analyzer.py`, `java_dataflow.py` | Java including Spring parameter binding |
| `go_engine/`, `csharp_analyzer.py`, `php_analyzer.py`, `ruby_analyzer.py` | Remaining full-AST languages |
| `<lang>_analyzer.py` (30+) | Pattern-aware detectors for the long tail of languages |

Full-AST languages produce structural evidence (`analysis_kind="syntax-ast"`,
`"taint_flow"`); pattern languages produce heuristic evidence
(`analysis_kind="pattern"`). The distinction is preserved all the way to the
output, so a caller can tell a proven data path from a regex match.

### 3. Specs instead of duplicated logic

Framework semantics — where routes are declared, what counts as an auth check,
what counts as an ownership constraint — live in declarative YAML under
`rules/specs/` (`python/django.yaml`, `python/flask.yaml`, `javascript/express.yaml`,
`java/spring.yaml`, …) and are loaded by `engine/spec_loader.py`.
`engine/spec_idor.py` evaluates the IDOR invariant against those specs:

1. a route parameter (or request field) is a taint source,
2. the value reaches a model/DB lookup,
3. no ownership or tenancy filter constrains the lookup,
4. no auth check guards the handler.

`guardmarly.frameworks.get_framework_spec(language, framework)` is the single
accessor, falling back to hand-written profiles where no YAML spec exists yet.

### 4. Interprocedural analysis

| Module | Role |
| --- | --- |
| `ir/global_graph.py` | Cross-file symbol/call graph with an interprocedural fixpoint |
| `ssa_taint.py`, `heap_taint.py` | SSA-lite taint propagation, including heap/field flows |
| `graph/` | Unified source graph, Java call graph, SQLite-backed graph store, cross-language bridges (Python/Go backend → JS frontend via route/HTTP matching) |
| `cpg/` | Code property graph queries for structural patterns |

### 5. Post-processing

Order matters, and each stage can only remove or re-weight evidence that the
previous stage produced:

1. **Config application** — custom sinks/sources, rule overrides, disabled rules.
2. **Inline suppressions** — `# guardmarly: ignore[...]` (see [Configuration](configuration.md)).
3. **Triage** (`engine/triage.py`) — drops findings that are provably
   test-fixture noise; serious CWEs are kept even in tests.
4. **Confidence** (`engine/confidence.py`) — taint-aware demotion: an
   injection/auth finding needs structural evidence plus a path to stay
   HIGH/CRITICAL.
5. **Clustering** (`engine/` incident clustering) — merges related findings.
6. **Baseline** — removes findings already accepted by the project.

### 6. Reporting

`reporters.py` renders text, JSON, SARIF 2.1.0, HTML and a CISO summary.
SARIF emits `codeFlows` for findings with a propagation path.
`baseline.py` computes stable fingerprints (`rule_id + normalised path +
dataflow-path hash`) so baselines survive refactors.

## The Rust core

`guardmarly_rust_core/` provides tree-sitter based parsing and a fast pattern
engine. When it is not compiled the scanner falls back to pure Python — slower,
never different in kind. `--fail-on-degraded` makes that fallback visible in CI
rather than silently accepting shallower analysis.

## Trust boundaries

- **No network at scan time.** Licences are Ed25519-signed tokens verified
  offline; the only outbound calls are ones you invoke (`license activate`,
  `--ai-remediate` against a local Ollama).
- **No telemetry.** Counters live in `~/.guardmarly/`.
- **Model-callable input.** Rule patterns are regex with a ReDoS circuit
  breaker (`dse.py`); community rules are parsed from a constrained YAML subset
  rather than a general loader.

## Extension points

| Goal | Where |
| --- | --- |
| Add a language pattern rule | `community_rules/*.yaml` |
| Add framework semantics | `rules/specs/<language>/<framework>.yaml` |
| Teach taint about your code | `guardmarly.json` (`sinks`, `sources`, `custom_sanitizers`) |
| Add a new analysis stage | `src/guardmarly/engine/` |
| Add an output format | `src/guardmarly/reporters.py` |
