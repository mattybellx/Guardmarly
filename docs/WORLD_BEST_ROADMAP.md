# Ansede Static — World's Best SAST Implementation Roadmap

**Created:** 2026-07-02 | **Current version:** v5.1.0 | **Tests:** 1,195 passing
**Goal:** Beat Semgrep and CodeQL on all fronts: recall, precision, speed, and usability.

---

## Phase A: OWASP Benchmark Dominance (Java Depth) ← ACTIVE

The OWASP Benchmark (2,740 Java test cases) is the only industry-standard SAST yardstick.
Current: **44.9% recall, 62.5% FPR**. Target: **90%+ recall, <20% FPR**.

### A1. ✅ Add CWE-330 (Weak Random) Detector
- **Current:** 25/218 TP (11.5% recall) — near-zero on 493 cases
- **Root cause:** No detector for `java.util.Random` vs `java.security.SecureRandom`
- **Fix:** Pattern match `new Random()` and `Math.random()` in security contexts
- **Files:** `java_ast_analyzer.py`
- **Safety:** Add-only detector, no existing rule modified
- **Tests:** Add to `test_java_csharp_analyzers.py`

### A2. ✅ Add CWE-614 (Insecure Cookie) Detector
- **Current:** Not tracked in OWASP breakdown
- **Root cause:** No detector for `cookie.setSecure(false)` or missing secure flag
- **Fix:** Pattern match `Cookie` construction without `.setSecure(true)` or with `.setSecure(false)`
- **Files:** `java_ast_analyzer.py`
- **Safety:** Add-only detector

### A3. ✅ Expand CWE-328 (Weak Hash) Coverage
- **Current:** 89/129 TP (69.0% recall) — partial coverage
- **Root cause:** `_check_weak_crypto` catches `MessageDigest.getInstance("MD5")` but misses `DigestUtils.md5Hex()`, `Hashing.md5()`, and variable-based algorithm selection
- **Fix:** Add Guava `Hashing.md5()`, Apache `DigestUtils.md5()`, and `"MD5"`/`"SHA-1"` string constant propagation
- **Files:** `java_ast_analyzer.py`
- **Safety:** Expand existing detector, tests verify no regression

### A4. 🔧 Wire IFDS Solver to Java Pipeline (Interprocedural Taint)
- **Current:** `v2/ifds.py` has complete IFDS solver (tabulation, flow functions, call/return edges) but is NOT wired to `java_ast_analyzer.py`
- **Root cause of low SQLi/XSS recall:** Taint doesn't flow across method boundaries
- **Fix:** Connect `IFDSSolver` to Java AST walker so `request.getParameter("id")` → `buildQuery(id)` → `stmt.execute(sql)` is tracked
- **Files:** `v2/ifds.py` → `java_ast_analyzer.py` (new bridge in `java_dataflow.py`)
- **Safety gate:** Run full OWASP benchmark before/after, verify recall improvement without FPR increase
- **Risk: MEDIUM** — new interprocedural flow could introduce false positives; gate with symbolic guards

### A5. 🔧 Add Trust Boundary (CWE-501) Detector
- **Current:** 31/83 TP (37.3% recall)
- **Root cause:** No distinction between request attributes (untrusted) and session attributes (trusted)
- **Fix:** Track `request.setAttribute()` vs `session.setAttribute()` dataflow
- **Files:** `java_ast_analyzer.py`
- **Safety:** Add-only detector

### A6. 🔧 XSS Interprocedural Flow (CWE-79)
- **Current:** 98/227 TP (43.2% recall) in OWASP
- **Root cause:** XSS detection only triggers on direct `response.getWriter().write(param)` — misses wrapper methods
- **Fix:** Wire IFDS so `String x = request.getParameter("x")` → `writeOutput(x)` → `response.getWriter().write(x)` is tracked
- **Files:** `java_dataflow.py`, `java_ast_analyzer.py`
- **Safety gate:** Verify no FP increase on clean code

---

## Phase B: CI/CD Adoption (SARIF + GitHub Action) ← ACTIVE

### B1. ✅ Wire SARIF Output
- **Current:** `sarif_validator.py` exists but `--format sarif` doesn't produce valid SARIF 2.1.0
- **Fix:** Build `src/ansede_static/reporters.py` SARIF formatter; validate with `sarif_validator.py`
- **Files:** `reporters.py`, `cli.py`
- **Safety:** Add-only formatter, no change to detection

### B2. 🔧 GitHub Action (`action.yml`)
- **Current:** `action.yml` scaffold exists but not functional
- **Fix:** Docker-based action that runs ansede, produces SARIF, uploads to GitHub Code Scanning
- **Files:** `action.yml`, `docker/static-scanner.Dockerfile`

### B3. 🔧 GitLab CI Template
- **Fix:** `.gitlab-ci.yml` with SARIF artifact
- **Files:** New `gitlab-ci.example.yml`

---

## Phase C: Performance (10k+ LOC/s)

### C1. 🔧 Rust Fast-Path for All Languages
- **Current:** Rust fast-path only for Python and JS
- **Fix:** Add Java, Go, C# tree-sitter grammars to `ansede_rust_core/`
- **Files:** `ansede_rust_core/src/`

### C2. 🔧 Parallel Batch Mode Optimization
- **Current:** `--batch --workers 8` achieves 6.16 KLOC/s
- **Target:** 10k+ LOC/s via shared GlobalGraph, pre-warmed rule cache, streaming output
- **Files:** `engine/async_scanner.py`

---

## Phase D: Competitive Benchmarking ← ACTIVE

### D1. ✅ Run 3-Tool Comparison After Changes
- **Script:** `benchmarks/one_click_compare.py`
- **Corpus:** 164 CVEs + OWASP Benchmark 2,740 cases
- **Tools:** Ansede (post-changes) vs Semgrep OSS vs CodeQL CLI
- **Output:** `benchmarks/comparison_july2_2026.json`

### D2. 🔧 OWASP Scorecard Publication
- **Target:** After A1-A6 complete, publish OWASP head-to-head
- **Output:** `benchmarks/owasp_scorecard_final.json`
- **Compare:** Ansede vs Semgrep vs CodeQL on OWASP Benchmark

---

## Phase E: Framework Depth (Spring/ASP.NET)

### E1. 🔧 Spring Security Symbolic Guards
- **Current:** Framework detector exists (`analysis/framework_detector.py`) but not wired to Java analyzer
- **Fix:** `@PreAuthorize`, `@Secured`, `@RolesAllowed` suppress false auth-bypass findings
- **Files:** `analysis/framework_detector.py`, `java_ast_analyzer.py`

### E2. 🔧 ASP.NET Core Patterns
- **Fix:** `[Authorize]`, `[AllowAnonymous]` guard detection for C#
- **Files:** `csharp_analyzer.py`

---

## Safety Gates (Non-Negotiable)

Every change must pass these gates before being considered complete:

| Gate | What | Command |
|---|---|---|
| **G1: Full test suite** | All 1,195+ tests pass | `pytest tests/ -q` |
| **G2: Quality benchmark** | 37/37 cases, 15/15 shadow detectors | `python -m benchmarks.quality_benchmark` |
| **G3: CVE recall** | 164/164 (100%) maintained | `python -m benchmarks.cve_recall_runner` |
| **G4: No regression on clean code** | 0 findings on known-clean repos | `python -m benchmarks.precision_benchmark` |
| **G5: OWASP recall improvement** | Recall increases without FPR increase | `python benchmarks/owasp_head_to_head.py` |

---

## Implementation Order (This Session)

1. ✅ Document roadmap (this file)
2. 🔧 CWE-330 weak random detector → run OWASP, verify improvement
3. 🔧 CWE-614 insecure cookie detector → run OWASP, verify improvement
4. 🔧 CWE-328 weak hash expansion → run OWASP, verify improvement
5. 🔧 SARIF output wiring → validate with sarif_validator
6. 🔧 Wire IFDS solver → run full safety gates
7. 🔧 Run 3-tool comparison → publish results

Each step: implement → test → benchmark → verify no regression → commit.
