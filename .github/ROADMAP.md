# Guardmarly: Roadmap to 40 Full-AST Languages

## Goal

40 languages with full taint-tracking, route-mapping, IDOR-detection AST analyzers.
Zero regression. Faster than today. No false positives on clean code. 100% CWE recall.

---

## Architecture: How to Add a Full-AST Language

Each new language needs 4 files:

```
src/guardmarly/<lang>_analyzer.py    # AST-walking security analyzer (~800-1500 lines)
src/guardmarly/<lang>_parser.py      # Tree-sitter or pure-Python parser
tests/test_<lang>.py                 # 50+ test cases (positive + negative)
rules/custom_checks.yaml             # 5-10 language-specific pattern rules
```

Plus wiring:
- `src/guardmarly/__init__.py` — extension list + scan_file dispatch
- `src/guardmarly/cli.py` — --lang choices + --stdin handler
- `guardmarly_rust_core/src/lib.rs` — tree-sitter grammar + supported_languages
- `vscode-extension/src/extension.ts` — language list + mapLanguage

---

## Phase 1: Pattern→AST Upgrade (existing 15 pattern-only languages)

Do these in order of highest user demand (search volume):

### Tier A — High demand, tree-sitter exists (1-2 weeks each)

| # | Language | Tree-sitter crate | Priority reason |
|---|---|---|---|
| 1 | **Ruby** | `tree-sitter-ruby` | 2.4k monthly searches, rails ecosystem |
| 2 | **PHP** | `tree-sitter-php` | 5.1k monthly searches, wordpress ecosystem |
| 3 | **Rust** | `tree-sitter-rust` | 3.8k searches, fast-growing |
| 4 | **Kotlin** | `tree-sitter-kotlin` (community) | Android ecosystem |
| 5 | **Swift** | `tree-sitter-swift` | iOS ecosystem |

### Tier B — Medium demand (2-3 weeks each)

| # | Language | Notes |
|---|---|---|
| 6 | **Scala** | JVM language, similar to Java analyzer patterns |
| 7 | **Dart** | Flutter ecosystem, high growth |
| 8 | **Elixir** | Phoenix framework, growing ecosystem |
| 9 | **Lua** | Game dev, nginx, embedded systems |
| 10 | **Clojure** | JVM, unique syntax requires different approach |

### Tier C — Config/Infra languages (1 week each)

| # | Language | Notes |
|---|---|---|
| 11 | **Dockerfile** | Regex-heavy, simple AST |
| 12 | **Terraform/HCL** | `tree-sitter-hcl`, infrastructure-as-code |
| 13 | **Shell/Bash** | `tree-sitter-bash`, massive attack surface |
| 14 | **YAML** | Kubernetes, CI configs, GitHub Actions |
| 15 | **Haskell** | Niche but high-signal (finance, blockchain) |

---

## Phase 2: New Languages (25→40)

After upgrading all pattern-only to full AST (15 more = 20 total), add 20 new ones:

### Quick wins — tree-sitter exists (1 week each)
- **C/C++** (`tree-sitter-c`, `tree-sitter-cpp`) — massive ecosystem
- **R** (`tree-sitter-r`) — data science
- **Julia** (`tree-sitter-julia`) — scientific computing
- **Zig** (`tree-sitter-zig`) — rising systems language
- **Nix** (`tree-sitter-nix`) — reproducible builds
- **Solidity** (`tree-sitter-solidity`) — smart contracts
- **Erlang** (`tree-sitter-erlang`) — telecom, distributed systems
- **Groovy** (`tree-sitter-groovy`) — Jenkins pipelines
- **OCaml** (`tree-sitter-ocaml`) — formal verification
- **Perl** (`tree-sitter-perl`) — legacy enterprise

### Medium effort (2 weeks each)
- **Objective-C** (`tree-sitter-objc`) — legacy iOS/macOS
- **Crystal** — Ruby-like compiled
- **Nim** — Python-like systems
- **F#** — .NET functional
- **Vala** — GNOME desktop
- **ReasonML** — React/OCaml hybrid

### Longer effort (3-4 weeks, custom parsers)
- **VBA** — massive legacy Office macros
- **PL/SQL** — Oracle stored procedures
- **ABAP** — SAP enterprise
- **COBOL** — banking mainframes (tiny niche but critical)

---

## Step-by-Step Process for Each Language

Use this exact sequence. Never skip steps. Run full test suite after every step.

### Step 1: Scaffold (30 min)
```bash
# Create parser stub
touch src/guardmarly/<lang>_parser.py
# Create analyzer stub
touch src/guardmarly/<lang>_analyzer.py
# Create test file
touch tests/test_<lang>.py
```

### Step 2: Wire tree-sitter (1 hour)
- Add crate to `guardmarly_rust_core/Cargo.toml`
- Add grammar match arm in `lib.rs` parse_with_language()
- Add to `supported_languages()`
- `cargo build --release` → commit Cargo.lock

### Step 3: Parser module (4-8 hours)
- Walk tree-sitter CST → normalized AST nodes
- Handle: function declarations, assignments, calls, imports, classes
- Write 20 parser tests first (TDD)

### Step 4: Analyzer module (8-20 hours)
Follow the pattern from `python_analyzer.py`:
1. Define taint sources (HTTP params, CLI args, env vars, file reads)
2. Define taint sinks (SQL, exec, file write, eval, deserialization)
3. Implement taint propagation (assignments, function calls, returns)
4. Route mapping (HTTP route → handler → auth check → DB query)
5. IDOR detection: route param flows to DB query without ownership filter

### Step 5: Rules (1 hour)
Add 5-10 YAML rules in `rules/custom_checks.yaml`:
- Hardcoded secrets pattern
- Unsafe function calls
- Weak crypto usage
- Missing CSRF protection

### Step 6: Test suite (4-8 hours)
Minimum 50 tests per language:
- 10 positive: known-vulnerable code (should find)
- 10 negative: clean code (should NOT find — zero FP guarantee)
- 10 edge cases: nested functions, async, decorators
- 10 realistic: mini-app with routes + DB
- 10 IDOR-specific: route→DB without auth

### Step 7: Performance (2-4 hours)
- Benchmark: 1,000+ LOC file scan time
- Profile: `python -m cProfile -s cumulative`
- Optimize hot paths (regex compilation, AST walking)
- Target: comparable to existing Python/JS analyzer speed

### Step 8: Wire everything (30 min)
- Add extension list to `__init__.py`
- Add to `scan_file()` dispatch
- Add to `cli.py` --lang choices + --stdin handler + `_analyze_file()`
- Add to VS Code extension language lists
- Run full test suite (1,183 tests) → must stay green

### Step 9: Regression guard (1 hour)
```bash
# Before merging any new language:
pytest tests/ -q --tb=short     # Must be 100% passing
pytest tests/ --durations=10     # Check nothing got slower
python -m guardmarly.cli tests/ --format json  # Real scan of test suite
```

---

## Testing Strategy to Build Training Data

### Automated corpus collection
```bash
# Scan random GitHub repos for real-world training data
python -m guardmarly.cli ~/repos/ --format json --output corpus_scan.json

# Extract findings for training:
# - True positives: known vulnerable patterns → improve detection
# - False positives: flagged clean code → improve triage
# - Missed findings: known vulns not caught → improve sink catalog
```

### Weekly benchmark routine
```bash
# Run against a fixed set of 50 diverse repos
# Track: detection count, FP count, scan time
# Goal: detection ↑, FP ↓, time ↓ every week
python scripts/benchmark_repos.py --repos repos.txt --output results/$(date +%Y-%m-%d).json
```

### Continuous improvement loop
1. Scan random repo → log findings
2. Human review 10 random findings → classify TP/FP
3. FP? → add sanitizer or context rule
4. Missed vuln? → add sink pattern or taint source
5. Repeat weekly

---

## Speed Optimization Checklist

After every 5 languages, run these optimizations:

### Immediate wins (already done)
- [x] Rust fast-path pattern engine (lib.rs)
- [x] File-level result cache (skip re-analysis)
- [x] ProcessPoolExecutor for multi-core

### Per-language optimizations
- [ ] Pre-compile all regex patterns at module load (not per-scan)
- [ ] Use `frozenset` for taint source/sink lookups (O(1) vs O(n))
- [ ] AST node id() memoization (already in Python, add to new langs)
- [ ] Skip whitespace-only lines before AST walking

### Global optimizations
- [ ] Shared rule compilation cache across all languages
- [ ] Incremental scan: only re-analyze changed files
- [ ] Tree-sitter query-based rules (faster than AST walk for simple patterns)
- [ ] Parallel file analysis by default (currently opt-in with --parallel)

---

## Zero Regression Guarantee

Before ANY merge to main:

```bash
# 1. Full test suite must pass
pytest tests/ -q --tb=short  # Must be 100%

# 2. Speed must not degrade
python scripts/perf_check.py  # Must be <= 120% of baseline

# 3. CVE recall benchmark must hold
python scripts/cve_recall.py  # Must be 100% (164/164)

# 4. Zero false positives on known-clean corpus
python scripts/fp_check.py  # Must be 0

# 5. New language test coverage
pytest tests/test_<lang>.py --cov=src/guardmarly/<lang>_analyzer --cov-report=term
```

If ANY of these fail, do not merge. Fix first.

---

## Priority Order (Highest Impact First)

Based on search volume × ecosystem size × implementation difficulty:

1. **PHP** — 5k searches, massive WP ecosystem, easy AST
2. **Ruby** — 2.4k searches, Rails ecosystem, medium AST
3. **Rust** — 3.8k searches, fast-growing, existing v0.1 analyzer
4. **Kotlin** — Android, medium AST
5. **Swift** — iOS, medium AST
6. **Dockerfile** — 1 week, huge attack surface
7. **Terraform** — infra-as-code, growing
8. **Shell** — massive attack surface
9. **C/C++** — biggest ecosystem, hard AST
10. **Dart** — Flutter, growing fast
