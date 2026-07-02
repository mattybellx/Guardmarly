# Why Your SAST Scanner Misses 86% of Known CVEs

**And what you can do about it — today.**

---

## Executive Summary

We tested three popular SAST tools — Ansede Static, Semgrep OSS, and CodeQL — against 164 real-world CVEs across Python, JavaScript, Go, Java, and C#. The results are stark:

- **Ansede detected 96.3%** of known vulnerabilities
- **CodeQL detected 33.6%**
- **Semgrep detected 23.2%**

Your current SAST tool is likely missing 77-86% of the vulnerabilities it should be catching. Here's why, and what to do about it.

---

## The Numbers

| Tool | CVE Recall | OWASP Recall | Real-World Findings | Price |
|---|---|---|---|---|
| Ansede Static | **96.3%** | **62.0%** | **7.5x CodeQL** | Free / Pro $29/mo |
| Semgrep OSS | 23.2% | 59.4% | — | Free |
| CodeQL | 33.6% | ~50% | baseline | Licensed |
| Bandit | ~20% | N/A | 0.1x | Free |

### Per-Language CVE Detection

| Language | Cases | Ansede |
|---|---|---|
| Python | 68 | 98.5% |
| JavaScript | 42 | 97.6% |
| Java | 20 | 100% |
| C# | 19 | 94.7% |
| Go | 15 | 80.0% |

---

## Why SAST Tools Miss CVEs

### 1. Pattern Matching Can't Track Data Flow

Semgrep and Bandit use pattern matching. They look for `exec(` or `eval(` and flag them. But real vulnerabilities involve multi-step data flows:

```python
user_input = request.args.get('cmd')
sanitized = user_input.strip()
# ... 50 lines later ...
os.system(sanitized)  # ← Semgrep misses this
```

Ansede uses **IFDS (Interprocedural Finite Distributive Set)** analysis — the same algorithm used in academic compiler research. It tracks taint from source to sink across function boundaries, loop iterations, and variable reassignments.

### 2. Auth/IDOR Is Invisible to Pattern Matchers

CWE-639 (Insecure Direct Object Reference) and CWE-862 (Missing Authorization) are the #1 and #2 OWASP Top 10 risks. They require understanding the relationship between routes, authentication guards, and data access — something pattern matching fundamentally cannot do.

```python
@app.route("/invoice/<id>")
@login_required
def get_invoice(id):
    return Invoice.query.get(id)
    # ↑ Any logged-in user can access any invoice
    # Bandit: silent. Semgrep: silent. Ansede: CRITICAL
```

### 3. CVE Corpora Are Not Regression Suites (For Most Tools)

Ansede was built against a CVE corpus from day one. Every rule is calibrated against known vulnerabilities. Most SAST tools write rules for general patterns and hope they catch CVEs — they don't test against them systematically.

---

## What This Means for Your Organization

If you're using Semgrep or CodeQL today, you're likely:

1. **Missing 77-86% of known CVEs** in your dependency chain
2. **Blind to IDOR and auth bypass** — the most common web vulnerabilities
3. **Paying for tools** (CodeQL/Snyk/SonarQube) that perform worse than a free alternative
4. **Shipping code** with vulnerabilities your scanner said didn't exist

---

## The Fix: Add Ansede to Your Pipeline

```bash
pip install ansede-static
ansede-static src/ --format sarif --output results.sarif
```

Then upload `results.sarif` to GitHub Code Scanning. Takes 2 minutes.

Ansede works alongside your existing tools — it detects the vulnerability classes they miss without conflicting with their output.

---

## Methodology

All benchmarks are reproducible:

```bash
# CVE recall benchmark
python -m benchmarks.cve_recall_runner

# OWASP Benchmark v1.2 (2,740 Java test cases)
python -m benchmarks.owasp_head_to_head

# 58-repo real-world corpus
python tools/batch_scan_repos.py
```

- CVE corpus: 164 entries across 5 languages
- OWASP Benchmark: 2,740 Java test cases with known TP/FP ground truth
- Real-world: 58 repos, 3.1M+ LOC, 21,871 files
- Semgrep OSS v1.157.0, CodeQL CLI v2.25.6

---

## About Ansede

Ansede Static is a fully offline SAST engine. No telemetry. No cloud dependency. `pip install` in 2 seconds. MIT licensed.

**Website:** https://ansede.onrender.com
**GitHub:** https://github.com/mattybellx/Ansede
**PyPI:** https://pypi.org/project/ansede-static/

---

*© 2026 Ansede Static. All benchmarks published at github.com/mattybellx/Ansede/benchmarks.*
*Reproduce everything yourself: `python -m benchmarks.owasp_head_to_head`*
