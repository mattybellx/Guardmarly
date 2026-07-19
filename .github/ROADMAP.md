# GUARDMARLY — MASTER INSTRUCTION FILE FOR AI CODING AGENTS

You are working on https://github.com/mattybellx/Guardmarly, a free, offline,
MIT-licensed SAST scanner. Read this entire file before writing any code.
Follow it exactly. If this file and the repository disagree, STOP and report
the discrepancy — do not guess.

---

## 1. MISSION

Make Guardmarly the most accurate **fully-offline** SAST scanner for
**authorization flaws** (IDOR / broken access control, CWE-639) and
injection-class bugs in web applications.

Priority order — never invert this:

1. Detection quality: measured precision + recall
2. Framework-aware depth in a small set of languages
3. Developer experience (DX)
4. Language breadth — LAST, and only after 1–3 are solid

### Explicitly out of scope

Do NOT build: SCA/dependency scanning, container/image scanning, secrets
scanning as a separate product, dashboards, web UI, compliance reporting
suites. Trivy, Grype, Gitleaks, and Checkov already do these well.
Integrate with them via SARIF output. If a task asks for one of these,
stop and flag it.

---

## 2. HARD RULES — NEVER VIOLATE

1. **No absolute claims.** Never write "100% recall", "0% false positives",
   "100% CWE coverage", or similar in code, docs, README, output, or commit
   messages. Always report measured numbers with the corpus named
   (e.g., "recall 91.2% on OWASP Benchmark 1.2, n=2,740").
2. **Never weaken tests to go green.** Do not delete, skip, or loosen a
   test, rule, sanitizer, or assertion to make CI pass. If a test is
   genuinely wrong, prove it, explain why in the commit message, and add a
   replacement test in the same commit.
3. **Every finding type needs both sides.** No new rule ships without ≥1
   positive test (must fire) and ≥1 negative test (must not fire).
4. **Run, then report.** Run the full test suite before claiming a task is
   done. Paste the actual command output. Never claim tests pass without
   running them in this session.
5. **One task per PR.** No drive-by edits, no reformatting unrelated files,
   no dependency upgrades unless the task requires them.
6. **No new runtime dependencies** without written justification in the PR
   description.
7. **Offline always.** No telemetry, no network calls at scan time, no
   phone-home of any kind. Ever.
8. **Stop on blockers.** If you cannot complete a step, report the blocker
   and stop. Do not improvise around it or silently skip it.

---

## 3. CURRENT STATE [UPDATED 2026-07-19]

Confirmed against the repo on 2026-07-19:

- **Full-AST analyzers**: Python, JavaScript/TypeScript, Go, Java, C#, PHP, Ruby
- **Pattern-aware analyzers** (~30+ additional): Kotlin, Swift, Dart, Lua, Elixir,
  Scala, Clojure, Haskell, Shell, Dockerfile, Terraform, YAML, C/C++, R, Julia,
  Zig, Nix, Solidity, Erlang, Groovy, OCaml, Perl, Objective-C, Crystal, Nim,
  F#, Vala, ReasonML, VBA, PL/SQL, ABAP, COBOL
- **Test count**: 1,336 passing, 18 xfailed (as of 2026-07-19, end of session)
- **Coverage**: 90% (spec_loader), 89% (spec_idor), 89% total engine modules
- **Rust core**: `guardmarly_rust_core/` (tree-sitter + fast pattern engine)
- **IR / engine**: `src/guardmarly/ir/` (GlobalGraph, interprocedural fixpoint),
  `src/guardmarly/engine/` (confidence, audit, clustering, symbolic guards,
  remediation, triage, shadow scan, PR generator, spec_loader, spec_idor)
- **Framework modules**: `src/guardmarly/frameworks/` — Django, Express, Spring,
  ASP.NET Core, Gin, Quarkus; unified `get_framework_spec()` API
- **Phase 0 (measurement harness)**: ✅ COMPLETE — `scripts/fetch_corpora.py`,
  `scripts/benchmark.py`, `scripts/perf_check.py`, `scripts/ci_improve.py`,
  `scripts/comprehensive_test.py`, `scripts/fresh_scan.py`, `scripts/quick_bench.py`
- **Phase 1 (declarative specs)**: ✅ COMPLETE — `rules/specs/` with 30 YAML specs,
  18 languages, spec_loader.py, spec_idor.py
- **Phase 3 (DX)**: ✅ COMPLETE — baseline, explain, GitHub Action, VS Code extension,
  autofix with 35 tests, `--pr` flag with 20 tests
- **Key paths**:
  - `src/guardmarly/<lang>_analyzer.py` — analyzers (~40+ files)
  - `src/guardmarly/<lang>_parser.py` — parsers (PHP, Ruby, Kotlin, Scala, Swift, Rust)
  - `src/guardmarly/__init__.py` — extension list + scan_file dispatch
  - `src/guardmarly/cli.py` — CLI, --lang, --stdin
  - `rules/custom_checks.yaml` — pattern rules
  - `community_rules/` — community-contributed YAML rules (~12 packs)
  - `guardmarly_rust_core/src/lib.rs` — grammars, supported_languages
  - `vscode-extension/src/extension.ts` — editor integration (v1.2.0)
  - `tests/test_<lang>.py` — per-language tests

---

## 4. PHASE 0 — MEASUREMENT HARNESS ✅ COMPLETE (2026-07-19)

### 4.1 Benchmark corpora

- ✅ `scripts/fetch_corpora.py` — clones/pins each corpus at a fixed commit
- ✅ 26 corpora defined across 3 categories:
  - **benchmark** (4): OWASP Benchmark Java, Juliet Java/C#/C++
  - **vulnerable** (6): DVWA, WebGoat, Juice Shop, RailsGoat, NodeGoat, PyGoat
  - **clean** (16): Flask, Django, FastAPI, Requests, Express, Lodash, React,
    Spring Framework, Guava, Kubernetes Client, ASP.NET Core, Roslyn, Go stdlib,
    Kubernetes, Gin, Laravel, Symfony, Rails, Ruby, TypeScript
- ✅ `.corpora/` gitignored (large binary repos)
- ✅ Manifest written to `.corpora/manifest.json`

### 4.2 Harness

- ✅ `scripts/benchmark.py` — runs Guardmarly against every corpus
- ✅ Category-specific metrics:
  - Benchmark suites: TP/FP/FN/precision/recall/F1 (parsed from expected results)
  - Vulnerable apps: finding counts by severity/CWE, CWE-639 IDOR count
  - Clean corpus: FP/kLOC as false-positive proxy
- ✅ Emits `results/benchmarks/<version>.json`
- ✅ `--compare` flag compares against committed baseline, flags regressions
- ✅ `--quick` mode for fast (5-file) sampling
- ✅ `--parallel N` for concurrent corpus scanning

### 4.3 Reporting rules

- Every benchmark report names corpus + version + counts
- Never round 99.4% up to "100%"
- The README may only cite numbers that exist in `results/benchmarks/`

---

## 5. PHASE 1 — SHARED ENGINE + DECLARATIVE SPECS ✅ IN PROGRESS (2026-07-19)

### 5.1 Problem

The old plan was ~40 hand-written analyzers at 800–1500 lines each. That
duplicates taint logic ~40×; every fix drifts. We build ONE engine instead.

### 5.2 Target architecture

```
tree-sitter parse → language parser → normalized IR
                                       ↓
                              semantic layer
                          (symbol tables, import
                           resolution, call graph)
                                       ↓
                          ONE taint/dataflow engine
                    (field-sensitive, inter-procedural,
                     records full propagation path)
                                       ↓
              language specs + framework specs (YAML)
```

### 5.3 Engine status

- ✅ **IR**: `src/guardmarly/ir/` — GlobalGraph, interprocedural fixpoint
- ✅ **Taint engine**: `src/guardmarly/ssa_taint.py` — SSA-lite taint analysis
- ✅ **Engine package**: `src/guardmarly/engine/` — confidence, audit, clustering,
  symbolic guards, remediation, triage, shadow scan, PR generator
- ✅ **Spec schema**: YAML-based declarative specs (this section)
- ✅ **Spec loader**: `src/guardmarly/engine/spec_loader.py` — zero-dependency
  YAML spec loading with caching and merge (core + framework)
- ✅ **Python core spec**: `rules/specs/python/core.yaml` — 16 sources, 19 sinks,
  10 sanitizers, 10 propagators
- ✅ **Django framework spec**: `rules/specs/python/django.yaml` — 4 sources,
  6 sinks, 5 sanitizers, 8 auth checks, 4 ownership checks, 3 route extractors,
  3 middleware patterns
- ⬜ **Port Python analyzer** to consume specs (deferred — current Python analyzer
  works well; spec porting is a refactor, not a feature add)
- ⬜ **Spec files for JS/TS, Go, Java, C#** — directories exist, specs TBD

### 5.4 The IDOR invariant (the core detection — implement exactly)

Flag IDOR when ALL of these hold for a route handler:

1. A route path parameter (or request param) is a source
2. That value flows (through ≥0 propagators) into a model/DB lookup sink
3. No ownership/tenancy filter constrains the lookup
4. No auth check protects the handler (per auth_checks + middleware chain)

Report the full path: source → each propagation step → sink, with
file:line at every step. A finding without a renderable path is a bug in
the engine.

### 5.5 Migration order

Port existing analyzers to the engine in this order, one PR each:
1. Python (reference implementation) — spec exists, port pending
2. JavaScript/TypeScript
3. Go
4. Java
5. C#

Each port must keep every existing test green and match or beat the old
analyzer's benchmark numbers.

---

## 6. PHASE 2 — FRAMEWORK DEPTH ✅ YAML SPECS COMPLETE (2026-07-19)

Framework semantics are where IDOR detection lives. YAML specs now exist
alongside the Python dataclass profiles.

| Language | Frameworks (priority order) | YAML Spec | Dataclass |
|---|---|---|---|
| Python | Django + DRF, Flask, FastAPI | ✅ django, flask | ✅ DjangoProfile |
| JS/TS | Express, NestJS, Next.js | ✅ express | ✅ ExpressProfile |
| Java | Spring | ✅ spring | ✅ SpringProfile, QuarkusProfile |
| C# | ASP.NET Core | ✅ aspnet | ✅ AspNetProfile |
| Go | net/http, Gin, Echo | ✅ gin | ✅ GinProfile |

### 6.1 Spec coverage summary

| Framework | Sources | Sinks | Sanitizers | Auth Checks | Ownership | Routes | Middleware |
|---|---|---|---|---|---|---|---|
| Django | 4 | 6 | 5 | 8 | 4 | 3 | 3 |
| Flask | 8 | 8 | 6 | 7 | 3 | 3 | 4 |
| Express | 8 | 14 | 7 | 5 | 3 | 3 | 3 |
| Spring | 10 | 9 | 5 | 8 | 3 | 3 | 3 |
| ASP.NET | 10 | 12 | 5 | 5 | 3 | 3 | 3 |
| Gin | 8 | 12 | 5 | 5 | 2 | 3 | 3 |

### 6.2 Unified API

``get_framework_spec(language, framework)`` in ``guardmarly.frameworks``
returns YAML ``SecuritySpec`` when available, falls back to Python dataclass
profile. This is the single entry point for analyzers.

Each framework spec ships with: ≥5 positive tests, ≥5 negative tests,
≥3 IDOR tests drawn from the framework's real auth patterns.

---

## 7. PHASE 3 — DEVELOPER EXPERIENCE ✅ MOSTLY COMPLETE (2026-07-19)

1. ✅ **Suppression comments.** `# guardmarly:ignore RULE-ID — reason`
   (adapt comment syntax per language). Warn on unused suppressions.
   Suppressions without a reason string are rejected.
2. ✅ **Baseline file.** `--baseline .guardmarly-baseline.json` suppresses
   known findings; `--write-baseline` regenerates. Fingerprint =
   rule_id + normalized path + dataflow-path hash. CLI exit code reflects
   only NEW findings (this is what makes PR gating usable).
3. ✅ **Path explanations.** Every taint finding prints:
   `source (file:line) → step (file:line) → … → sink (file:line)`,
   plus a one-paragraph remediation hint.
4. ✅ **GitHub Action.** `guardmarly/action` — scans, diffs against baseline,
   uploads SARIF to code scanning, fails the check on new findings.
5. ✅ **Autofix.** `--apply-fixes` / `--guarded-fix` flags apply safe
   code transformations. Covers:
   - Python: CWE-89 (f-string→parameterized), CWE-78 (shell=True→False),
     CWE-502 (pickle→json), CWE-22 (path traversal)
   - Java: JV-001 (add @PreAuthorize), JV-002 (findById→findByIdAndUserId)
   - C#: CS-001 (add [Authorize]), CS-002 (FindAsync→owner-scoped)
   - Safety gate: blocks heuristic injection-class CWEs from autofix
   - Backups created before modifications
   - ✅ 35 autofix tests added 2026-07-19 (previously untested)

---

## 8. PHASE 4 — NEW LANGUAGES ✅ SPECS COMPLETE (2026-07-19)

### 8.1 Priority — ALL TIERS DONE

Tier 1 ✅: **PHP** (Laravel spec), **Ruby** (Rails spec) — plus core specs
Tier 2 ✅: **Dockerfile, Terraform/HCL, YAML, Shell/Bash** — core/terraform specs
Tier 3 ✅: **Kotlin, Swift, Dart, Scala, Elixir, C/C++, Lua** — core specs (2026-07-19)

### 8.2 Spec inventory — 30 specs, 18 languages

| Language | Core | Frameworks |
|---|---|---|
| Python | ✅ | Django, Flask, FastAPI |
| JavaScript | ✅ | Express, NestJS, Next.js |
| Java | ✅ | Spring |
| C# | ✅ | ASP.NET Core |
| Go | ✅ | Gin, Echo |
| PHP | ✅ | Laravel |
| Ruby | ✅ | Rails |
| Kotlin | ✅ | — |
| Swift | ✅ | — |
| Dart | ✅ | — |
| Scala | ✅ | — |
| Elixir | ✅ | — |
| C/C++ | ✅ | — |
| Lua | ✅ | — |
| Dockerfile | ✅ | — |
| HCL | — | Terraform |
| Shell | ✅ | — |
| YAML | ✅ | — |

### 8.3 Known traps (spike before committing)

- Ruby: metaprogramming (`method_missing`, `define_method`, `send`) —
  document what the resolver cannot see; degrade gracefully, never crash
- PHP: WordPress hook/filter dispatch is dynamic — model `add_action`/
  `do_action` as explicit propagator edges
- C/C++: preprocessor — require `compile_commands.json` or use fuzzy
  parsing mode; document which
- Kotlin/Swift: community tree-sitter grammars vary in quality — parse a
  50-file corpus first; if >5% of files produce error nodes, stop and
  report before writing the analyzer

### 8.3 Known traps (spike before committing)

- Ruby: metaprogramming (`method_missing`, `define_method`, `send`) —
  document what the resolver cannot see; degrade gracefully, never crash
- PHP: WordPress hook/filter dispatch is dynamic — model `add_action`/
  `do_action` as explicit propagator edges
- C/C++: preprocessor — require `compile_commands.json` or use fuzzy
  parsing mode; document which
- Kotlin/Swift: community tree-sitter grammars vary in quality — parse a
  50-file corpus first; if >5% of files produce error nodes, stop and
  report before writing the analyzer

---

## 9. QUALITY GATES — RUN IN ORDER, ALL MUST PASS BEFORE ANY MERGE

```bash
pytest tests/ -q --tb=short                    # 1. 100% pass, zero skips added
pytest tests/ --durations=20                   # 2. no test >2× prior duration
python scripts/perf_check.py                   # 3. ≤120% of committed baseline
python scripts/benchmark.py --compare          # 4. recall must not DROP;
                                               #    FP count on clean corpus must not RISE
pytest tests/test_ --cov= --cov-report=term   # 5. ≥90% on changed module
python -m guardmarly.cli . --format json       # 6. self-scan: no new findings
```

Gate 4 replaces the old "must be 100% (164/164)" rule. We never regress,
and we report honestly — we do not demand a fixed perfect number that
invites overfitting.

If any gate fails: fix the cause, never the gate.

---

## 10. CONTINUOUS IMPROVEMENT LOOP (weekly, may be agent-assisted)

1. Scan a fresh sample of public repos → `corpus_scan.json`
2. Sample 10 findings for human review → classify TP/FP
3. FP → add/adjust sanitizer or context rule, WITH a regression test
   capturing that exact FP
4. Missed vuln → extend spec (new source/sink/propagator), WITH a test
5. Append results to `results/benchmarks/`; trend must be: recall ↑,
   FP ↓, time ↓

---

## 11. DEFINITION OF DONE (per task)

- [ ] All gates in section 9 pass, output pasted in PR
- [ ] New behavior has positive AND negative tests
- [ ] Every taint finding renders a full source→sink path
- [ ] Specs/rules documented in the PR description
- [ ] CHANGELOG updated
- [ ] No absolute claims anywhere in the diff
- [ ] Works with network disabled (`pytest` with network off must pass)

---

## 12. STOP CONDITIONS — HALT AND ASK A HUMAN

- Benchmark recall drops vs baseline and you can't explain why
- Fixing an FP seems to require deleting a rule or test
- A tree-sitter grammar errors on >5% of its corpus
- This file conflicts with repo reality
- A task seems to require network access at scan time, telemetry, or a
  feature listed as out of scope (section 1)
- You're about to write "100%" or "zero false positives" anywhere

---

## 13. ORDERED BACKLOG — ALL COMPLETE ✅ (2026-07-19)

1. ✅ Phase 0: `scripts/fetch_corpora.py` + `scripts/benchmark.py` (2026-07-19)
2. ✅ Phase 1: Spec schema + spec loader + Python core + Django (2026-07-19)
3. ✅ Phase 1: Core YAML specs for JS, Java, C#, Go, PHP, Ruby (2026-07-19)
4. ✅ Phase 2: YAML framework specs — Django, Flask, FastAPI, Express, NestJS,
   Next.js, Spring, ASP.NET Core, Gin, Echo, Laravel, Rails (2026-07-19)
5. ✅ Phase 4 Tier 2: Dockerfile, Terraform/HCL, Shell/Bash, YAML specs (2026-07-19)
6. ✅ Phase 4 Tier 3: Kotlin, Swift, Dart, Scala, Elixir, C/C++, Lua specs (2026-07-19)
7. ✅ Unified API: `get_framework_spec()` in `guardmarly.frameworks` (2026-07-19)
8. ✅ Phase 3: Autofix tests — 35 tests (2026-07-19)
9. ✅ Spec-augmented IDOR engine: `src/guardmarly/engine/spec_idor.py` +
   60 tests, 89% coverage — cross-references findings against 30 YAML specs (2026-07-19)
10. ✅ Wire spec_idor into CLI post-processing (2026-07-19)
11. ✅ Coverage push to 89-90% (2026-07-19)
12. ✅ CI improvement loop with trend tracking (2026-07-19)
13. ✅ Fortune 500 virgin scan validation (2026-07-19)
14. ✅ DeepSeek V4 remediation playbook: trust & credibility fixes (2026-07-19)
15. ✅ Repo hygiene: 12,350 vendor files untracked (2026-07-19)

### Next strategic horizon (not yet committed)

- Port Python analyzer to consume specs as primary source
- First committed benchmark baseline on 26 corpora
- JS agent section in audit.py for better JS-specific classification
- Auto-suggested heuristics for CWE-362, CWE-601, CWE-1333
- Validate on 100+ top-starred GitHub repos

### Spec inventory (30 specs, 18 languages)

| Language | Core | Frameworks |
|---|---|---|
| Python | ✅ | Django, Flask, FastAPI |
| JavaScript | ✅ | Express, NestJS, Next.js |
| Java | ✅ | Spring |
| C# | ✅ | ASP.NET Core |
| Go | ✅ | Gin, Echo |
| PHP | ✅ | Laravel |
| Ruby | ✅ | Rails |
| Kotlin | ✅ | — |
| Swift | ✅ | — |
| Dart | ✅ | — |
| Scala | ✅ | — |
| Elixir | ✅ | — |
| C/C++ | ✅ | — |
| Lua | ✅ | — |
| Dockerfile | ✅ | — |
| HCL | — | Terraform |
| Shell | ✅ | — |
| YAML | ✅ | —
