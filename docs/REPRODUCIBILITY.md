# Reproducing Ansede Benchmarks

> Anyone can reproduce these results in under 15 minutes.

## Prerequisites

```bash
# Python 3.9+ required
pip install ansede-static
# Or from source:
git clone https://github.com/mattybellx/Ansede.git
cd Ansede
pip install -e ".[test]"
```

## 1. Run Unit Tests

```bash
python -m pytest tests/ -q -k "not phase2_registry"
# Expected: 1,026 passed, 0 failed
```

## 2. Run Gold-Standard Assessment

```bash
python -c "
import sys; sys.path.insert(0,'src')
# See gold_standard_assessment.json for full 100-snippet results
# Reproduce by running each snippet through:
#   analyze_python(code, filename='test.py')  # for Python
#   run_js_analysis(code, filename='test.js') # for JS
"
```

## 3. Run CVE Recall Benchmark

```bash
python -m benchmarks.cve_recall_runner
# Expected: Recall ~90%, Precision ~88%
```

## 4. Run Competitive Comparison

```bash
pip install bandit  # optional
python -c "
# Run the same 50-snippet corpus through Ansede and Bandit
# Compare TP/FP/TN/FN metrics
"
```

## 5. Run Stress Test

```bash
python phase_g_stress.py
# Scans src/, tests/, vscode-extension/ directories
# Expected: 0 errors, 100% stability
```

## Key Files

| File | Purpose |
|---|---|
| `gold_standard_assessment.json` | 100-snippet blind eval results |
| `blind_eval_v2_report.json` | 50-snippet eval v2 |
| `blind_eval_v3_report.json` | 50-snippet eval v3 |
| `phase_fg_report.json` | Competitive benchmark + stress test |
| `phase_g_expanded_stress.json` | Multi-directory stress test |
| `PRODUCTION_ROADMAP.md` | Full production readiness plan |
| `docs/DETECTION_COVERAGE.md` | CWE coverage matrix |
