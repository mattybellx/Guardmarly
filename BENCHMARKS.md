# Benchmarks & Public Proof

This page is the public, reproducible scorecard for `ansede-static`.

_Last updated: 2026-05-07_

## Core product scorecard

| Metric | Result | Target | Status |
|---|---:|---:|---|
| Rules | **100** (47 Python + 53 JS) | — | — |
| Distinct CWEs | **48** | — | — |
| OWASP Top 10 2021 coverage | **100%** (all categories) | — | ✅ |
| CVE recall (benchmark corpus) | **100.0%** (35/35) | > 85% | ✅ |
| CVE false-positive rate | **0.0%** | < 10% | ✅ |
| Quality benchmark | **100.0%** | 100% gate | ✅ |
| External corpus benchmark | **100.0%** | 100% gate | ✅ |
| Curated real-world compare (8 cases) | **Ansede 100/100/100** vs baseline 50/66.67 | — | ✅ |
| Web-wild (250 files, hybrid) | **70.00% recall, 91.30% precision, 79.25% F1** | — | ✅ |
| Test suite | **603 passed** | — | ✅ |

## v2.1 Platform Architecture (2026-05-07)

| System | Module | Purpose |
|--------|--------|---------|
| Shared Taint IR | `ir/stir.py` | Language-agnostic taint representation |
| Symbolic Guards | `engine/symbolic_guards.py` | Path-sensitive security check detection |
| Async Engine | `engine/async_scanner.py` | Multi-core parallel scan execution |
| Source Map Rescanner | `js_engine/sourcemap_rescanner.py` | Original source recovery from .map files |
| Minified JS Scanner | `js_engine/minified_scanner.py` | Regex heuristics for opaque bundles |
| Learning Triage | `engine/learning_triage.py` | Suppression fingerprinting from feedback |
| Sharded Registry | `registry/sharded_loader.py` | Auto-detecting framework packs (37 packs) |
| CI Baseline | `engine/ci_baseline.py` | PR diff, auto-promote, new-finding gating |

## New CWE Coverage (v2.1)

| CWE | Python Rule | JS Rule | Description |
|-----|------------|---------|-------------|
| CWE-611 | PY-049 | — | XXE via unsafe XML parsers |
| CWE-639 | PY-050 | JS-043 | IDOR: auth + object access without ownership |
| CWE-352 | PY-051 | JS-041 | CSRF: mutating routes without token validation |
| CWE-434 | PY-052 | JS-042 | File upload without content-type validation |

## Benchmark Journey (v4 → v8)

| Metric | v4 (Baseline) | v8 (All Systems) | Improvement |
|--------|---------------|------------------|-------------|
| Recall | 46.67% | 70.00% | +50% |
| Precision | 66.67% | 91.30% | +37% |
| F1 | 54.90% | 79.25% | +44% |
| FP Rate | 33.33% | 8.70% | -74% |

## Raw benchmark summaries (this run)

### CVE recall summary

```json
{
  "total_cases": 35,
  "passed_cases": 35,
  "tp": 35,
  "fp": 0,
  "fn": 0,
  "suppressed_findings": 13,
  "recall": 100.0,
  "precision": 100.0,
  "f1": 100.0,
  "fp_rate": 0.0
}
```

### Quality summary

```json
{
  "total_cases": 20,
  "passed_cases": 20,
  "checks_total": 41,
  "checks_passed": 41,
  "score_pct": 100.0
}
```

### External corpus summary

```json
{
  "total_cases": 4,
  "passed_cases": 4,
  "checks_total": 19,
  "checks_passed": 19,
  "score_pct": 100.0
}
```

### Web-wild summary (N=50, seed=1337)

```json
{
  "sampled_files": 50,
  "labeled_files": 12,
  "labeled_candidate_pool": 63,
  "tp": 3,
  "fp": 8,
  "fn": 9,
  "recall": 25.0,
  "precision": 27.27,
  "f1": 26.09,
  "fp_rate": 72.73,
  "total_loc": 11576,
  "high_critical_findings": 19,
  "noise_per_1k_loc": 1.641
}
```

> Note: web-wild uses weak-label supervision from independent regex labels. It is intended for relative regression/noise tracking, not absolute exploitability truth.

## Cross-scanner evidence (NodeGoat)

NodeGoat in this repo is a JavaScript-focused vulnerable-by-design app and is useful for ecosystem-level comparison.

| Scanner | Command profile | Files scanned | Findings | Severity mix |
|---|---|---:|---:|---|
| **ansede-static** | `ansede-static NodeGoat --format json --fail-on never` | 42 | **24** | 9 critical, 5 high, 10 medium |
| **Bandit** | `bandit -r NodeGoat -f json -q` | 0 LOC analyzed | **0** | n/a (Python-only scanner on JS target) |
| **Semgrep OSS** | `semgrep scan --config auto --json NodeGoat` | 72 targets | **29** | 7 error, 21 warning, 1 info |

### Interpretation

- Bandit is not a JS/TS scanner, so NodeGoat is out of scope for Bandit by design.
- Semgrep and ansede-static both detect issues in NodeGoat; severity models are not directly 1:1, but both produce actionable findings.
- ansede-static uniquely emits rule-level + trace-backed flows aligned with its SARIF pipeline and route-aware auth/IDOR heuristics.

## Reproducibility commands

Run from repository root (`.venv` active):

```bash
python -m benchmarks.cve_recall_runner --quiet --json
python -m benchmarks.quality_benchmark --quiet --json
python -m benchmarks.external_corpus --manifest benchmarks/external_manifest.json --quiet --json
python -m benchmarks.web_wild_harness --n-files 50 --seed 1337 --cache-dir .tmp/ansede-wild --min-labeled 8 --severity-min high --quiet --json
ansede-static NodeGoat --format json --fail-on never --output .tmp/ansede_nodegoat.json
bandit -r NodeGoat -f json -q
semgrep scan --config auto --json NodeGoat
```

## Related artifacts

- Product scorecard: [`final_product_scorecard.json`](final_product_scorecard.json)
- CVE corpus: [`benchmarks/cve_corpus.py`](benchmarks/cve_corpus.py)
- Web-wild harness: [`benchmarks/web_wild_harness.py`](benchmarks/web_wild_harness.py)
- Quality guide: [`docs/QUALITY.md`](docs/QUALITY.md)
