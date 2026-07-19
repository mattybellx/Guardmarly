# Claims and Evidence

This document tracks claims made about Guardmarly and the evidence supporting them.
Evidence is scoped to specific corpora, versions, and methodologies. No universal
or absolute claims are made.

## Detection Claims

### CVE Recall

**Claim**: Detects known-vulnerability patterns across a published benchmark corpus.
**Evidence**: 164 CVE test cases across Python, JavaScript, Go, Java, and C#.
Results measured on the internal CVE corpus (version 6.3.0, July 2026).
**Limitations**: Results depend on corpus composition. Not a claim of universal
recall. New CVE patterns may not be detected until rules are updated.

### IDOR / CWE-639 Detection

**Claim**: Detects Insecure Direct Object Reference patterns across framework-aware
route analysis.
**Evidence**: 23 framework test cases (11 vulnerable, 12 safe) across Django, Flask,
FastAPI, Express, NestJS, Next.js, Spring, ASP.NET Core, Gin, Echo, Laravel, Rails.
All vulnerable cases detected; all safe cases correctly identified (July 2026).
**Limitations**: Detection depends on framework signature matching. Custom or
unusual framework patterns may not be detected.

### False Positive Rate

**Claim**: Production code false-positive rates vary by language.
**Evidence** (100-file samples, July 2026):
- Go/Gin: 0.6 findings/kLOC
- Python/Django: 10.3 findings/kLOC
- Python/Flask: 17.0 findings/kLOC
- JavaScript/Express: 29.0 findings/kLOC
**Limitations**: These are self-scan results on open-source repos. Rates will vary
by codebase. The scanner's own source code (src/guardmarly/) produces findings
because rule catalog strings self-match. CI self-scan excludes src/ for this reason.

## Performance Claims

**Claim**: Average throughput on the samples/ benchmark corpus.
**Evidence**: 1,727 LOC/s on 23,268 LOC across 189 files (July 2026).
**Limitations**: Throughput varies significantly by file size, language, and
analysis depth. Go scans faster than Python; JavaScript is fastest.

## Language Support

**Claim**: Currently dispatches analysis for 40+ file types.
**Evidence**: See `src/guardmarly/__init__.py` for the full extension-to-analyzer
dispatch map. 5 languages have full-AST analysis; the remainder use pattern-based
detection.
**Limitations**: Pattern-only languages detect fewer vulnerability classes than
full-AST languages.

## Methodology

### How to Reproduce

```bash
# Test suite
pip install -e ".[dev]"
pytest tests/ -q

# Benchmark
python scripts/fresh_scan.py
python scripts/ci_improve.py --scan-only

# Performance
python scripts/perf_check.py
```

### Benchmark Principles

1. Corpus must be documented (what, when, how fetched)
2. Tool versions must be pinned
3. Results must be machine-readable and committed
4. Limitations must be published alongside results
5. "100%" claims are never made — always cite measured count

### False Positive Adjudication

1. Define the clean corpus before running tools
2. Two-pass review for disputed findings
3. Record: confirmed TP, confirmed FP, needs review, tooling/config issue
4. Never collapse "needs review" into "0% false positives"

## Historical Note

Earlier versions of Guardmarly documentation (pre-July 2026) contained absolute
claims (e.g., "100% CVE recall", "zero false positives", "world-first"). These
have been removed in favor of the measured, scoped approach documented here.
The CHANGELOG retains historical entries for transparency.
