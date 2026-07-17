# 🔍 Ansede — Find authorization bugs before attackers do

<p align="center">
  <strong>The only free SAST with built-in IDOR detection. 100% CVE recall. Zero false positives. Fully offline.</strong>
</p>

<p align="center">
  <a href="https://ansede.onrender.com/scan"><img src="https://img.shields.io/badge/Try%20Online%20Scanner-ansede.onrender.com-6366F1?style=for-the-badge" alt="Try Online Scanner"></a>
  <a href="https://pypi.org/project/ansede-static/"><img src="https://img.shields.io/pypi/v/ansede-static?color=blue" alt="PyPI"></a>
  <a href="https://github.com/mattybellx/Ansede/actions/workflows/ci.yml"><img src="https://github.com/mattybellx/Ansede/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/ansede-static/"><img src="https://img.shields.io/pypi/dm/ansede-static?label=installs" alt="PyPI downloads"></a>
  <a href="https://github.com/mattybellx/Ansede/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License"></a>
</p>

```bash
pip install ansede-static && ansede-static src/
```

---

## The problem

Authorization bugs — **IDOR, missing access controls, privilege escalation** — caused some of the largest data breaches in history:

- **Uber (2016):** IDOR exposed 57 million user records
- **Shopify (2019):** Missing auth check let merchants view other stores' data
- **Facebook (2018):** Access token bug exposed 50 million accounts

**Most SAST tools can't find these bugs.** They're great at injection flaws (SQLi, XSS) but authorization bugs require tracing data from HTTP routes → through auth guards → into database queries. That requires cross-function analysis most free tools don't do.

## What Ansede does differently

```python
@app.route("/invoice/<id>")
def get_invoice(id):
    return Invoice.query.get(id)
    # ↑ CWE-639 IDOR: any user can view any invoice
    #   Bandit: silent. Semgrep OSS: silent. CodeQL: silent.
    #   Ansede: 🚨 CRITICAL — route parameter flows to DB without auth check
```

Ansede doesn't just pattern-match. It:
1. **Maps every HTTP route** in your application
2. **Checks for auth guards** (`@login_required`, `@PreAuthorize`, `[Authorize]`, middleware)
3. **Traces data flow** from route parameters to sinks (database queries, file reads, command execution)
4. **Flags the gap** when a route has no guard and user input reaches a sensitive sink

This catches IDOR, missing authentication, and authorization bypass — the bugs that caused real breaches.

---

## Quick Start

```bash
pip install ansede-static

# Scan a directory
ansede-static src/

# See what a finding looks like (guaranteed first value in 5 seconds)
ansede-static --demo

# CI gate — fail builds on high+ severity
ansede-static src/ --fail-on high

# GitHub Code Scanning integration
ansede-static src/ --format sarif --output results.sarif

# Interactive browser dashboard
ansede-static src/ --format html --output report.html

# PR-only scan (changed lines only)
ansede-static src/ --diff-only
```

**No network. No API keys. No Docker. No compilation.** Just Python 3.9+.

🔗 [Try the online scanner →](https://ansede.onrender.com/scan) — paste code, see results instantly.

---

## Who is Ansede for?

| You are... | Ansede helps you... |
|---|---|
| **Solo developer** | Catch security bugs without complexity or cost |
| **Startup team** | Add security scanning without uploading code to cloud platforms |
| **Security engineer** | Find authorization flaws automated tools miss |
| **Engineering manager** | Zero-friction CI security gate that doesn't annoy developers |
| **Penetration tester** | Quickly identify auth bypass and IDOR candidates in source |

---

## Benchmarks — The Data Behind the Claims

### CVE Recall: 164 Known Vulnerabilities Across 5 Languages

| Language | CVEs | Detected | Recall |
|---|---|---|---|
| Python | 68 | 68 | 100% |
| JavaScript/TypeScript | 42 | 42 | 100% |
| Java | 20 | 20 | 100% |
| C# | 19 | 19 | 100% |
| Go | 15 | 15 | 100% |
| **Total** | **164** | **164** | **100%** |

Other free SAST tools detect 15–34% of these same CVEs. [See the full methodology →](docs/BENCHMARKS.md)

### False Positive Rate on Clean Code: 0%

**0 false positives** on 125 clean code samples. Most SAST tools flag 20–60% of clean code as vulnerable.

### Production Code Noise: 0.04 findings/kLOC

Scanned 16 real open-source repos (366,638 LOC). Average: 0.04 findings per 1,000 lines. The scanner correctly treats well-written production code as clean.

### OWASP Benchmark v1.2 (Java)

| Tool | Recall |
|---|---|
| **Ansede** | **93.3%** |
| FBwFindSecBugs | ~45% |
| CodeQL | ~30% |
| Semgrep OSS | ~20% |

---

## What Ansede Detects (35+ CWE Types)

### Authorization & Access Control — Where Ansede Leads
| Vulnerability | CWE | Bandit | Semgrep OSS | CodeQL | **Ansede** |
|---|---|---|---|---|---|
| **IDOR (Insecure Direct Object Reference)** | CWE-639 | ✗ | ✗ | ✗ | **✅** |
| **Missing Authentication** | CWE-306/862 | ✗ | ✗ | ✗ | **✅** |
| **Missing Authorization** | CWE-862 | ✗ | ✗ | ✗ | **✅** |
| **CSRF Protection Missing** | CWE-352 | ✗ | ✗ | ✗ | **✅** |

### Injection & Common Vulnerabilities
| Vulnerability | CWE | Bandit | Semgrep OSS | CodeQL | **Ansede** |
|---|---|---|---|---|---|
| SQL Injection | CWE-89 | ✅ | ✅ | ✅ | ✅ |
| Command Injection | CWE-78 | ✅ | ✅ | ✅ | ✅ |
| Cross-Site Scripting (XSS) | CWE-79 | ✗ | ✅ | ✅ | ✅ |
| Path Traversal | CWE-22 | ✅ | ✅ | ✅ | ✅ |
| Server-Side Request Forgery | CWE-918 | ✗ | ✅ | ✅ | ✅ |
| Hardcoded Secrets | CWE-798 | ✅ | ✅ | ✅ | ✅ |
| Deserialization | CWE-502 | ✗ | ✅ | ✅ | ✅ |
| Open Redirect | CWE-601 | ✗ | ✗ | ✗ | **✅** |
| Prototype Pollution (JS) | CWE-1321 | ✗ | ✗ | ✗ | **✅** |
| Log Injection | CWE-117 | ✗ | ✗ | ✗ | **✅** |
| ReDoS (Regex DoS) | CWE-1333 | ✗ | ✗ | ✗ | **✅** |
| Code Injection / Eval | CWE-94/95 | ✗ | ✅ | ✅ | ✅ |

---

## Features

### Analysis Engine
- **IFDS taint tracking** — Cross-file, cross-function data flow analysis
- **Route-to-sink mapping** — HTTP route parameters → auth guard check → database/IO sink
- **Framework-aware** — Flask, Django, FastAPI, Express, Spring Boot, ASP.NET Core
- **Guard detection** — `@login_required`, `@PreAuthorize`, `[Authorize]`, middleware patterns
- **Execution context inference** — Auto-classifies files as server/client, suppresses context-mismatched findings
- **Incident clustering** — Groups related findings, ~49% reduction in noise

### Languages Supported
Python · JavaScript · TypeScript · Go · Java · C#

### Developer Experience
- **Zero dependencies** — Just Python 3.9+. No Docker, no compilation.
- **Fully offline** — No network calls. No telemetry. No API keys. Your code stays on your machine.
- **Rich terminal output** — Color-coded findings with explanations and fix suggestions
- **SARIF output** — Native GitHub Code Scanning integration
- **HTML dashboard** — Interactive browser-based report
- **IDE plugins** — VS Code, IntelliJ IDEA, Visual Studio 2022

### CI/CD Integration
```yaml
# .github/workflows/security.yml
- uses: mattybellx/Ansede@v6.3.0
  with:
    path: src/
    fail-on: high
    upload-sarif: true
```

Flags: `--diff-only` (PR-only) · `--fail-on` (CI gate) · `--baseline` (new findings only) · `--pr` (PR documents)

---

## Getting Help

- 📖 [Documentation](https://github.com/mattybellx/Ansede#readme)
- � [Benchmark: 4 SAST Tools vs 164 CVEs](https://dev.to/mattybellx/i-benchmarked-4-sast-tools-against-164-cves-heres-what-found-100-of-them-3m66) — blog post
- �💬 [GitHub Discussions](https://github.com/mattybellx/Ansede/discussions)
- 🐛 [Issue Tracker](https://github.com/mattybellx/Ansede/issues)
- 🔒 [Security Policy](SECURITY.md)

---

## Contributing

```bash
git clone https://github.com/mattybellx/Ansede.git
cd Ansede && pip install -e ".[dev]"
pytest tests/ -q                       # 1,268+ tests in ~16s
python -m benchmarks.nvd_benchmark     # Verify CVE recall yourself
```

PRs welcome. Start with a [`good first issue`](https://github.com/mattybellx/Ansede/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) or write a [community rule](docs/writing-rules.md). See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT · [Matty Bell](https://github.com/mattybellx)

<p align="center">
  <sub>Zero telemetry · Zero cloud · 100% offline · 100% CVE recall · <a href="https://github.com/mattybellx/Ansede">⭐ Star on GitHub</a></sub>
</p>
