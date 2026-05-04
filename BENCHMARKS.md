# Benchmarks & Public Proof

This page is the public, reproducible scorecard for `ansede-static`.

_Last updated: 2026-05-04_

## Core product scorecard

| Metric | Result | Target | Status |
|---|---:|---:|---|
| Rules | **96** (43 Python + 53 JS) | — | — |
| Distinct CWEs | **46** | — | — |
| OWASP Top 10 2021 coverage | **100%** (all categories) | — | ✅ |
| CVE recall (benchmark corpus) | **100.0%** (35/35) | > 85% | ✅ |
| CVE false-positive rate | **0.0%** | < 10% | ✅ |
| Quality benchmark | **100.0%** | 100% gate | ✅ |
| External corpus benchmark | **100.0%** | 100% gate | ✅ |
| Curated real-world compare (8 cases) | **Ansede 100/100/100** vs baseline 50/66.67 | — | ✅ |
| Web-wild (80 files, hybrid, balanced) | **100/100/100 — 0 FP, 0 FN** | — | ✅ |
| Web-wild (200 files, hybrid, balanced) | **100/100/100 — 0 FP, 0 FN** | — | ✅ |
| Test suite | **541 passed** | — | ✅ |

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
