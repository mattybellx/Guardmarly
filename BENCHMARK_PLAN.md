# Ansede Benchmark & Validation Plan

> **Goal:** Replace subjective "we scanned random repos" claims with objective, reproducible, competitive metrics against Juliet, OWASP, and CVE benchmarks.

> **Generated:** 2026-07-13 | **Status:** In Progress

---

## Table of Contents

1. [Juliet Test Suite](#1-juliet-test-suite)
2. [OWASP Benchmark](#2-owasp-benchmark)
3. [CVE Corpus Regression Gate](#3-cve-corpus-regression-gate)
4. [Self-Scan Dogfooding](#4-self-scan-dogfooding)
5. [Competitive Benchmark (vs Semgrep & CodeQL)](#5-competitive-benchmark)
6. [Targeted CWE Campaigns](#6-targeted-cwe-campaigns)
7. [Final Scorecard Publication](#7-final-scorecard-publication)

---

## 1. Juliet Test Suite

**What:** NIST's Juliet Test Suite — 100K+ test cases with known-good and known-bad variants per CWE. Labeled: every file is either `good` (safe pattern) or `bad` (vulnerable pattern).

**Why:** Gives exact precision/recall/F1 per CWE per language. Reproducible by anyone. Industry standard.

### Steps

1. **Download** from NIST SAMATE: `wget https://samate.nist.gov/SARD/downloads/test-suites/...`
2. **Extract** to `benchmarks/juliet/`
3. **Run ansede** on each language subset (C, Java, C# — Juliet has these)
4. **Parse results** against labeled ground truth
5. **Compute**: precision, recall, F1 per CWE, per language
6. **Compare** with published Semgrep & CodeQL Juliet scores

### Expected Output

```
CWE-89 (SQLi):    P=78% R=94% F1=0.85
CWE-79 (XSS):     P=65% R=88% F1=0.75
CWE-22 (PathTrav): P=82% R=91% F1=0.86
CWE-78 (CmdInj):  P=71% R=96% F1=0.82
...
```

### Status: 🔴 Not Started

---

## 2. OWASP Benchmark

**What:** OWASP Benchmark Project — 2,740 test cases across 11 CWE categories. Java-focused. Labeled TP/FP.

**Why:** Semgrep and CodeQL publish scores against this. Lets you say "Ansede scores X% vs Semgrep Y% on OWASP."

### Steps

1. **Clone** `https://github.com/OWASP-Benchmark/BenchmarkJava`
2. **Build** with Maven
3. **Run ansede** on the compiled/raw source
4. **Run OWASP scorecard generator** to get standard metrics
5. **Compare** with published scores

### Expected Output

```
OWASP Benchmark Score: 72% (Semgrep: 54%, CodeQL: 68%)
```

### Status: 🔴 Not Started

---

## 3. CVE Corpus Regression Gate

**What:** The existing 164-CVE corpus that Ansede already scores 100% on. Wire it as a CI gate.

**Why:** Catches regressions before they merge. Any PR that drops CVE recall below 100% fails.

### Steps

1. **Create** `.github/workflows/cve-regression.yml`
2. **Run** `benchmarks/cve_recall_runner.py` on every PR
3. **Fail** if recall < 100% or cases increase
4. **Publish** recall trend graph

### Status: 🔴 Not Started

---

## 4. Self-Scan Dogfooding

**What:** Run Ansede on its own source code. Audit every finding. Fix every FP pattern.

**Why:** Fastest way to find and fix FPs. Zero external dependency. Dogfooding builds credibility.

### Steps

1. **Run** `ansede src/ --no-triage` to get all raw findings
2. **Audit** every finding against source
3. **Fix** FP patterns in triage engine or rules
4. **Re-scan** to verify fixes
5. **Track** findings-over-time as metric

### Expected Output

```
Self-scan findings: 47 → 12 after fixes (74% reduction)
```

### Status: 🔴 Not Started

---

## 5. Competitive Benchmark (vs Semgrep & CodeQL)

**What:** Automated script that runs all 3 scanners on the same corpus and produces comparison tables.

**Why:** One command to prove competitive positioning. Reproducible by third parties.

### Steps

1. **Create** `benchmarks/competitive_bench.py`
2. **Run** ansede, semgrep (check if installed), codeql (check if installed)
3. **Score** all three against Juliet + OWASP + CVE corpus
4. **Generate** markdown comparison table

### Expected Output

```
| CWE | Ansede | Semgrep | CodeQL |
|-----|--------|---------|--------|
| 89  | 94%    | 78%     | 82%    |
| 79  | 88%    | 65%     | 71%    |
...
```

### Status: 🔴 Not Started

---

## 6. Targeted CWE Campaigns

**What:** For each top CWE, find 10 real-world repos with known vulnerabilities (via GitHub commit search), test detection.

**Why:** Proves real-world efficacy beyond synthetic benchmarks.

### Steps

1. **Search** GitHub: `"CWE-89" fix` or `"SQL injection" vulnerability` in commits
2. **Clone** the repo at the vulnerable commit
3. **Run** ansede — does it find the vuln?
4. **Record** detection rate per CWE

### Status: 🔴 Not Started

---

## 7. Final Scorecard Publication

**What:** A single `BENCHMARK_SCORECARD.md` file with all metrics, auto-generated.

**Why:** One link to prove Ansede's capabilities. Investors, users, competitors all want one thing: numbers.

### Steps

1. **Aggregate** all benchmark results
2. **Generate** scorecard markdown
3. **Publish** in repo root
4. **Update** on every release

### Expected Output

```markdown
# Ansede Benchmark Scorecard
## v6.2.2 — 2026-07-13

### Juliet Test Suite
| Language | Precision | Recall | F1 |
|----------|-----------|--------|----|
| Java     | 76%       | 94%    | 0.84 |
...

### OWASP Benchmark
Score: 72% (Semgrep: 54%, CodeQL: 68%)

### CVE Corpus
Recall: 100% (164/164)

### Self-Scan
FP rate: 12 findings in src/ (down from 47)
```

### Status: 🔴 Not Started

---

## Execution Order

1. ✅ Self-scan (dogfooding) — fastest wins, no external deps
2. ✅ CVE regression CI — protects existing 100% recall
3. ✅ Juliet Test Suite — gives defensible per-CWE metrics
4. ✅ OWASP Benchmark — gives competitive comparison
5. ✅ Competitive benchmark script — automates everything
6. ✅ Targeted CWE campaigns — real-world validation
7. ✅ Final scorecard — publish
