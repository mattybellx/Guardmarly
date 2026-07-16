# 🔍 Ansede Static · Python & JavaScript SAST Scanner

<p align="center">
  <strong>What your SAST misses: 77% of known CVEs.<br>What Ansede catches: <em>100%</em>. Fully offline. Zero noise.</strong>
</p>

<p align="center">
  <a href="https://ansede.onrender.com/scan"><img src="https://img.shields.io/badge/Try%20Online%20Scanner-ansede.onrender.com-6366F1?style=for-the-badge" alt="Try Online Scanner"></a>
  <a href="https://pypi.org/project/ansede-static/"><img src="https://img.shields.io/pypi/v/ansede-static?color=blue" alt="PyPI"></a>
  <a href="https://github.com/mattybellx/Ansede/actions/workflows/ci.yml"><img src="https://github.com/mattybellx/Ansede/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/ansede-static/"><img src="https://img.shields.io/pypi/dm/ansede-static?label=installs" alt="PyPI downloads"></a>
</p>

```bash
pip install ansede-static && ansede-static src/
```

---

## Why Ansede? The data.

| | Ansede | Other Free SAST Tools |
|---|---|---|
| **CVE Recall** (164 known vulns) | **100%** | 15–34% |
| **False Positives** (clean code) | **0%** (0/125) | High to Very High |
| **CWE-639 IDOR Detection** | ✅ World-first open-source | ❌ Not available in any free tool |
| **Offline / Zero Dependencies** | ✅ No network, no build | Varies |
| **Languages** | Python, JS/TS, Go, Java, C# | Varies |
| **Scan Speed** | ~750 LOC/s | 50–5,000 LOC/s |

> **20 real-world repos scanned. 3,143 files. 1.6M+ LOC.** Zero crashes. Zero false positives on clean code. [Full benchmarks →](docs/BENCHMARKS.md)

Most free SAST tools stop at injection bugs. Ansede catches what they miss — the **authorization flaws** behind real data breaches:

```python
@app.route("/invoice/<id>")
def get_invoice(id):
    return Invoice.query.get(id)
    # ↑ CWE-639 IDOR: any user can view any invoice
    #   Bandit: silent. Semgrep OSS: silent. Ansede: 🚨 CRITICAL
```

---

## Quick Start

```bash
pip install ansede-static
ansede-static src/                    # Scan a directory
ansede-static src/ --format sarif     # GitHub Code Scanning integration
ansede-static src/ --fail-on high     # CI gate (exit 1 on findings)
ansede-static src/ --format html      # Interactive browser dashboard
ansede-static src/ --diff-only        # PR-only scan (changed lines)
```

**No network. No API keys. No Docker. No compilation.** Just Python 3.9+.

🔗 [Try the online scanner →](https://ansede.onrender.com/scan) — paste code, see results instantly.

---

## Benchmarks

### CVE Recall — 164 Known Vulnerabilities Across 5 Languages

| Language | CVEs | Detected | Recall |
|---|---|---|---|
| Python | 68 | 68 | 100% |
| JavaScript/TypeScript | 42 | 42 | 100% |
| Java | 20 | 20 | 100% |
| C# | 19 | 19 | 100% |
| Go | 15 | 15 | 100% |
| **Total** | **164** | **164** | **100%** |

Other free SAST tools detect 15–34% of these same CVEs. [Reproduce it yourself →](docs/REPRODUCIBILITY.md)

### False Positive Rate — 125 Random Clean Snippets

**0 false positives.** The scanner correctly identifies all 125 clean code samples. Most SAST tools flag 20–60% of clean code as vulnerable. [See the data →](eval_500_report.json)

### Golden Corpus — 11 CWE Pairs, 100% Precision & Recall

Every CWE has a paired test: `vulnerable.*.test` (must trigger) + `secure.*.test` (must stay clean). All 11 pairs pass. [See golden corpus →](.ansede/golden_corpus/)

### OWASP Benchmark v1.2

| Tool | Recall |
|---|---|
| **Ansede** | **93.3%** |
| FBwFindSecBugs | ~45% |
| CodeQL | ~30% |
| Semgrep OSS | ~20% |

---

## Features

- **35+ CWE types** — SQLi, XSS, IDOR, auth bypass, SSRF, path traversal, command injection, hardcoded secrets, deserialization, prototype pollution, open redirect, log injection, ReDoS, and more
- **5 languages** — Python, JavaScript/TypeScript, Go, Java, C#
- **World's first free IDOR scanner** — Route-aware: maps HTTP routes → auth guards → data sinks
- **Zero false positives on clean code** — 125/125 clean snippets correctly identified
- **Fully offline** — No network calls. No telemetry. No API keys. Your code stays on your machine.
- **IFDS taint tracking** — Cross-file, cross-function data flow analysis
- **Execution context inference** — Auto-classifies files as server/client, suppresses context-mismatched findings
- **Guard detection** — `@login_required`, `@PreAuthorize`, `[Authorize]`, middleware patterns
- **Incident clustering** — Groups related findings, ~49% noise reduction
- **SARIF output** — Native GitHub Code Scanning integration
- **IDE plugins** — VS Code, IntelliJ IDEA, Visual Studio 2022
- **CI/CD ready** — `--diff-only`, `--fail-on`, `--baseline`, `--pr` flags

---

## GitHub Actions

```yaml
- uses: mattybellx/Ansede@v6.3.0
  with:
    path: src/
    fail-on: high
    upload-sarif: true
```

---

## Comparison: What Each Tool Actually Detects

| Vulnerability | Bandit | Semgrep OSS | CodeQL | **Ansede** |
|---|---|---|---|---|
| SQL Injection | ✓ | ✓ | ✓ | ✓ |
| Cross-Site Scripting | ✗ | ✓ | ✓ | ✓ |
| Command Injection | ✓ | ✓ | ✓ | ✓ |
| Path Traversal | ✓ | ✓ | ✓ | ✓ |
| Hardcoded Secrets | ✓ | ✓ | ✓ | ✓ |
| SSRF | ✗ | ✓ | ✓ | ✓ |
| **IDOR (CWE-639)** | ✗ | ✗ | ✗ | **✓ Built-in** |
| **Missing Auth (CWE-862)** | ✗ | ✗ | ✗ | **✓ Built-in** |
| **Prototype Pollution (CWE-1321)** | ✗ | ✗ | ✗ | **✓ Built-in** |
| **Log Injection (CWE-117)** | ✗ | ✗ | ✗ | **✓ Built-in** |
| **Open Redirect (CWE-601)** | ✗ | ✗ |✗ | **✓ Built-in** |

---

## Contributing

```bash
git clone https://github.com/mattybellx/Ansede.git
cd Ansede && pip install -e ".[dev]"
pytest tests/ -q                       # 1,268 tests in ~16s
python -m benchmarks.nvd_benchmark     # Verify CVE recall yourself
```

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT · [Matty Bell](https://github.com/mattybellx)

<p align="center">
  <sub>Zero telemetry · Zero cloud · 100% offline · 100% CVE recall · <a href="https://github.com/mattybellx/Ansede">⭐ Star on GitHub</a></sub>
</p>
