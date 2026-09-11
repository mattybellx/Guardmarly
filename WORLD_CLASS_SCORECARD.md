# World-class scanner scorecard

Every criterion a scanner must meet to be defensibly called *the best*, with the
current status, the evidence, and the test that guards it. **A criterion may only
be marked ✅ when a committed, reproducible check passes — not when it is
believed to be true.**

Legend: ✅ verified · ⚠️ verified but below target · ❌ not met

| # | Criterion | Status | Evidence | Guarded by |
| --- | --- | --- | --- | --- |
| 1 | Identical input produces identical output | ✅ | deterministic across 3 and 5 runs, all filter stages | `benchmarks/check_determinism.py` |
| 2 | Same tree scanned two ways agrees | ❌ | Python fixed (79→89 recovered); JavaScript still path-dependent (89 vs 96) | `benchmarks/check_path_independence.py` |
| 3 | Recall on labelled vulnerabilities | ✅ 97.2% | 35/36 — vs Semgrep 61.1%, Bandit 50.0% | `benchmarks/run_benchmark.py labelled` |
| 4 | False positives on trusted code | ❌ 0.55/kLOC | 189 kLOC stdlib — vs Semgrep 0.39, Bandit 0.42 | `benchmarks/compare_clean.py` |
| 5 | No false positives on clean controls | ❌ 36.8% | 7/19 — vs Semgrep 5/19, Bandit 1/8 | `benchmarks/run_benchmark.py labelled` |
| 6 | Throughput at scale | ❌ 1,716 LOC/s | vs Semgrep 6,144 (3.6×), Bandit 17,665 (10×) | `benchmarks/compare_clean.py` |
| 7 | Beats OSS alternatives on detection | ✅ | **35/36 vs Semgrep 22/36**; guardmarly found 13 fixtures Semgrep missed and missed none it found | `benchmarks/run_benchmark.py headtohead` |
| 8 | Multi-language detection, measured | ⚠️ | 5 languages, 14 CWE classes, per-language figures not yet split | corpus manifest |
| 9 | CI blocks regressions in the above | ❌ | checks exist but are not wired into `.github/workflows/` | — |
| 10 | Silent-failure paths eliminated | ⚠️ | 9 defects found & fixed; context-triage drop count surfaced; other drops un-audited | defect log §0 |
| 11 | Standards output validated | ⚠️ | SARIF reporter exists; schema validation not gated by a test | — |
| 12 | Evidence is third-party reproducible | ✅ | no network, no credentials, no licence | `benchmarks/README.md` |

## Where it stands against the best — measured, not claimed

Identical corpus directory, same machine, one run each.
**189 kLOC of Python standard library** (code a reviewer calls clean) and the
**55-file labelled corpus**:

| Tool | Recall | HIGH+/kLOC (clean) | HIGH+ on clean | LOC/s |
| --- | --- | --- | --- | --- |
| **Guardmarly** | **97.2%** | 0.55 | 104 | 1,716 |
| Semgrep `p/default` | 61.1% | **0.39** | 73 | 6,144 |
| Bandit 1.9.4 (Python only) | 50.0% | 0.42 | 79 | **17,665** |

**Guardmarly is first on recall and last on both precision and speed.** That is
the honest summary. The recall win is not marginal: it detected **13 fixtures
Semgrep missed and missed none that Semgrep found**. The precision and speed
deficits are equally real.

### Why the throughput gap is larger than it looks

`--parallel` / `--workers` advertise worker *processes*, but on this corpus
`--workers 8` measured **122.0s against 104.6s** for the default path — process
parallelism is **slower**, and the automatic path uses threads, which cannot
parallelise CPU-bound Python. So throughput is effectively single-core:
≈ 1,700 LOC/s regardless of worker count. The 30-file micro-benchmark did
improve 1.6× (41.9s → 26.3s) from the `_rule_46` hoist, which means the analyzer
is not the binding constraint at scan level — the surrounding pipeline is.

### How it can definitely be better

Ranked by measured value, each independently verifiable:

1. **Real process parallelism.** Threads give no speedup for CPU-bound analysis.
   Measured 3.6× gap to Semgrep and 10× to Bandit. A `ProcessPoolExecutor` over
   file batches, with the thread-local caches already in place, is the single
   largest available win and needs no algorithm change.
2. **Precision to ≤ 0.25/kLOC.** 104 HIGH+ findings on trusted code against
   Semgrep's 73. The noise is concentrated: `PY-012` (`exec`/`eval` in `bdb`,
   `doctest`, `dataclasses` — intentional uses) plus registry TOCTOU/XXE rules.
   Suppressing four rule families is measurable and bounded work.
3. **Clean-control false positives to 0.** Four of seven are one registry rule
   pair (`flask/auth/no-login-required`, `flask/headers/missing-hsts`) firing on
   fragment-sized files — a context problem with a known fix shape.
4. **JavaScript path independence.** Closes criterion 2 and the last recall miss.
5. **CI thresholds** so 1–5 cannot regress.

None of these require changing the detection engine, which is already the
strongest of the three measured.

## Criteria met since the last review

**1 — determinism (was ❌).** Root cause was not the analyzer but
`_taint_source_cache` / `_sink_name_cache`: module-level dicts keyed on
`(lineno, col_offset, type)`, a key unique only *within one file*, shared by the
CLI's thread pool. Two workers read each other's entries. This was a
*correctness* bug, not merely cosmetic — a trivial `hashlib.sha256` helper was
reported carrying a neighbouring file's SSRF finding. Caches are now
thread-private.

**3 — recall 91.7% → 97.2% (was ⚠️).** Two of the three "misses" were never
detection gaps: `python/open_redirect.py` and `python/weak_hash_md5.py` were
being *suppressed* because `python_analyzer`'s own private path helpers
(`_is_test_file`, `_is_framework_internal_python_path`, …) matched markers
against the **host** path. An absolute path under `…/benchmarks/…` looked like
test code. All five helpers now delegate to `ContextAnalyzer._match_path`.

**7 — head-to-head 12/14 → 14/14 (was ✅, improved).** Guardmarly now detects
every Python fixture in the corpus; Bandit detects 7 of 14.

## What remains, and what "yes" requires

* **2 — JavaScript path independence.** The remaining 89-vs-96 gap is JS-only
  (`JS-034` CWE-862, `JS-041` CWE-352). `js_engine/project_context.py` was
  routed through the scoped path and the gap did **not** close, so the
  suppressant is elsewhere — the next step is to run
  `check_path_independence.py` against an instrumented `js_analyzer` to find
  which branch the absolute form takes. Until this is green, two users
  scanning the same JavaScript get different answers.
* **4 — precision (0.55/kLOC).** Down from the previously published 2.10, but the
  earlier 0.46 figure was measured while the cache contamination was *losing*
  findings, so 0.55 is the honest corrected value. Remaining volume is led by
  `PY-012` (`exec`/`eval` in `bdb`, `doctest`, `dataclasses` — intentional
  uses) and registry TOCTOU/XXE rules.
* **5 — clean controls (36.8%).** Four of seven false-positive files come from
  `registry/flask/auth/no-login-required` and
  `registry/flask/headers/missing-hsts` firing on fragment-sized Flask files.
* **6 — throughput.** Needs the `--batch` path measured and a parallel mode that
  preserves the determinism guarantee won in criterion 1.
* **9 — CI.** `benchmarks/run_benchmark.py` must run on every push with
  thresholds (recall ≥ 0.95, HIGH+/kLOC ≤ 0.60) so criteria 1–5 cannot regress.
* **10 — silent drops.** Only the context-triage drop is reported today.
* **11 — SARIF.** Add a test that validates emitted SARIF against the 2.1.0
  schema.