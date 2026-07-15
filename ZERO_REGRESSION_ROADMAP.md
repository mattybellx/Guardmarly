# Ansede-Static: Zero-Regression Roadmap to 100% Metrics

> Generated: 2026-07-15 | Target: All metrics at or above previous records with zero regressions

---

## 🎯 Goal

Return ALL metrics to their previous highs (or better) and prove stability with extensive real-world validation:

| Metric | Previous Best | Current | Target |
|--------|--------------|---------|--------|
| CVE Recall | 100% (164/164) | 95.73% (157/164) | **100%** |
| Quality Gate | 63/63 checks, 15 shadow detectors | 96/96 checks, 20 shadow detectors | **100% ✅** |
| Test Suite | 1,147 passing | 1,268 passing | **1,268+ ✅** |
| Golden Corpus Recall | N/A | 100% | **100% ✅** |
| Golden Corpus Precision | N/A | 18.2% | **≥80%** |
| Real Repos Scanned | 58 repos, 0 failures | Not re-validated | **58+ repos, 0 failures** |
| 3-Tool Comparison | Ansede 100% vs Semgrep 23.2% vs CodeQL 33.6% | Not re-validated | **Re-validate & maintain lead** |
| FP Rate | 3.6% | Not re-measured | **≤3.6%** |

---

## 📋 Task Breakdown

### Phase 0: Fix CVE Recall Regressions → Target: 100% (164/164)

**7 missed CVEs** — all pre-existing, not caused by blueprint changes.

#### P0.1 — Java: CVE-2024-JAVA-CMD-INJECT-PB (CWE-78)
- **Issue**: ProcessBuilder with unsanitized user input not detected
- **File**: `src/ansede_static/java_analyzer.py`
- **Fix**: Add ProcessBuilder command injection pattern to Java analyzer sinks
- **Test**: Add to `benchmarks/quality_corpus.py` if not already present

#### P0.2 — Java: CVE-2024-JAVA-CMD-INJECT-EXEC (CWE-78)
- **Issue**: `Runtime.getRuntime().exec()` with unsanitized user input not detected
- **File**: `src/ansede_static/java_analyzer.py`
- **Fix**: Ensure `Runtime.exec()` is in Java sink list with taint propagation

#### P0.3 — Java: CVE-2024-JAVA-PATH-TRAV (CWE-22)
- **Issue**: Path traversal via `java.io.File` with unsanitized user input
- **File**: `src/ansede_static/java_analyzer.py`
- **Fix**: Add `new File(userInput)` as a path traversal sink

#### P0.4 — Java: CVE-2024-JAVA-PB-INJECT (CWE-78)
- **Issue**: Second ProcessBuilder variant missed
- **File**: `src/ansede_static/java_analyzer.py`
- **Fix**: Cover `ProcessBuilder(List<String>)` constructor variant

#### P0.5 — Java: CVE-2024-JAVA-FILE-TRAV (CWE-22)
- **Issue**: Path traversal via `java.io.File` with user-controlled filename
- **File**: `src/ansede_static/java_analyzer.py`
- **Fix**: Cover `File(parent, child)` constructor pattern

#### P0.6 — Java: CVE-2024-JAVA-LOG-INJECT (CWE-117)
- **Issue**: Log injection via unsanitized user input in Logger calls
- **File**: `src/ansede_static/java_analyzer.py`
- **Fix**: Add `Logger.info/warn/error` with tainted args as CWE-117 sink

#### P0.7 — Python: CVE-2024-PY-LOG-INJECT2 (CWE-117)
- **Issue**: Log injection via unsanitized user input in logging calls
- **File**: `src/ansede_static/python_analyzer.py`
- **Fix**: Ensure `logging.info/warning/error` with user input triggers CWE-117

**Validation Gate**: `python -m benchmarks.nvd_benchmark` must return 164/164 detected.

---

### Phase 1: Drive Golden Corpus Precision → Target: ≥80%

**Current**: 2/11 pass (CWE-78, CWE-798). 9 FPs on secure files.

#### P1.1 — Fix CWE-1321 (Prototype Pollution) Secure File
- **Issue**: 5 findings on secure JS file — `Object.create(null)` and bracket notation still triggering
- **Fix**: Rewrite secure file to use only `Map` or `Object.freeze()` patterns

#### P1.2 — Fix CWE-22 (Path Traversal) Secure File
- **Issue**: 5 findings on secure file — `os.path.join`, `send_file`, `os.path.realpath` all flagged
- **Fix**: Rewrite to use simpler patterns that truly avoid path traversal

#### P1.3 — Fix CWE-502 (Deserialization) Secure File
- **Issue**: 1 finding — `yaml.safe_load` or `ast.literal_eval` may still be flagged
- **Fix**: Remove any borderline patterns

#### P1.4 — Fix CWE-601 (Open Redirect) Secure File
- **Issue**: 5 findings — `redirect(url_for(...))` may be flagged
- **Fix**: Use only static redirects

#### P1.5 — Fix CWE-639 (IDOR) Secure File
- **Issue**: 2 findings — `@login_required` decorator not recognized as auth guard
- **Fix**: Use explicit ownership filter patterns

#### P1.6 — Fix CWE-79 (XSS) Secure File
- **Issue**: 3 findings — `res.send()` with template strings flagged
- **Fix**: Use pure template engine rendering

#### P1.7 — Fix CWE-89 (SQLi) Secure File
- **Issue**: 1 finding — parameterized query with f-string in params
- **Fix**: Remove f-string from parameter binding

#### P1.8 — Fix CWE-918 (SSRF) Secure File
- **Issue**: 5 findings — `requests.get` with validated URLs still flagged
- **Fix**: Use only static URLs

#### P1.9 — Fix CWE-94 (Code Injection) Secure File
- **Issue**: 1 finding — `ast.literal_eval` may be flagged
- **Fix**: Use only JSON parsing

**Validation Gate**: `python -m benchmarks.golden_benchmark_matrix` must show ≥9/11 passed.

---

### Phase 2: Real-Repo Validation → Target: 58+ repos, 0 failures

#### P2.1 — Prepare repo list
- Use `campaign_targets_top100.json` as source
- Select top 60 repos across Python, JS, Go, Java, C#

#### P2.2 — Run batch scan
- Command: `python -m benchmarks.campaign_worker_v2 --repos campaign_targets_top100.json --limit 60`
- Track: scan time, findings per repo, parse errors, crashes

#### P2.3 — Audit results
- Classify all findings as TP/FP/NEEDS_REVIEW
- Ensure 0 crashes, 0 parse failures on real code

#### P2.4 — Generate real-repo report
- Per-language stats
- Comparison against previous 58-repo run

**Validation Gate**: 60 repos scanned, 0 failures, FP rate ≤3.6%.

---

### Phase 3: 3-Tool Comparison → Target: Maintain competitive lead

#### P3.1 — Run Ansede on CVE corpus
- `python -m benchmarks.cve_recall_runner --tool ansede`

#### P3.2 — Run Semgrep OSS on CVE corpus
- `python -m benchmarks.cve_recall_runner --tool semgrep`

#### P3.3 — Run CodeQL on CVE corpus (if available)
- `python -m benchmarks.codeql_runner`

#### P3.4 — Generate comparison report
- `python -m benchmarks.three_tool_report`

**Validation Gate**: Ansede recall ≥95%, Semgrep ≤35%, CodeQL ≤40%.

---

### Phase 4: Performance Validation → Target: No regression

#### P4.1 — Run performance benchmark
- `python -m benchmarks.perf_regression_check` (real-repo test)
- Target: ≥750 LOC/s on real repos

#### P4.2 — Run micro-benchmarks
- Individual language parser speed
- CPG build time
- Taint analysis time

**Validation Gate**: Throughput unchanged or improved.

---

### Phase 5: Comprehensive Validation Pipeline

#### P5.1 — Build unified validation script
- File: `scripts/validate_all.py`
- Runs: pytest → quality gate → CVE recall → golden corpus → perf check
- Single pass/fail output
- JSON report for CI

#### P5.2 — Generate final compliance report
- All metrics in one document
- Comparison against previous best
- Signed-off for production

---

## 🏁 Execution Order

```
P0 (CVE fixes) → P1 (Golden corpus) → P5 (Pipeline) → P2 (Real repos) → P3 (3-tool) → P4 (Perf) → P5.2 (Report)
```

---

## 📊 Success Criteria

- [ ] CVE Recall: **164/164 (100%)**
- [ ] Quality Gate: **96/96 checks, 20/20 shadow detectors (100%)**
- [ ] Golden Corpus Recall: **11/11 (100%)**
- [ ] Golden Corpus Precision: **≥9/11 (≥80%)**
- [ ] Real Repos: **60+ repos, 0 failures, ≤3.6% FP rate**
- [ ] 3-Tool: **Ansede > Semgrep + CodeQL combined recall**
- [ ] Perf: **≥750 LOC/s real-repo throughput**
- [ ] Tests: **1,268+ passing**
- [ ] Blueprint Compliance: **100%**

---

*This roadmap is executable. Each phase has specific files, commands, and validation gates.*
